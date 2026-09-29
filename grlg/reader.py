"""
GRLG Zero-Copy Binary Search Reader.

Performs sub-microsecond IP lookups via mmap over flat array intervals.
"""

import mmap
import struct
import socket
from typing import Optional, Union
from dataclasses import dataclass

@dataclass(frozen=True)
class GeoFlags:
    value: int

    @property
    def is_datacenter(self) -> bool:
        return bool(self.value & 0x0001)

    @property
    def is_residential(self) -> bool:
        return bool(self.value & 0x0002)

    @property
    def is_mobile(self) -> bool:
        return bool(self.value & 0x0004)

    @property
    def is_commercial(self) -> bool:
        return bool(self.value & 0x0008)

    @property
    def is_spam(self) -> bool:
        return bool(self.value & 0x0100)

    @property
    def is_scanner(self) -> bool:
        return bool(self.value & 0x0200)

    @property
    def is_botnet(self) -> bool:
        return bool(self.value & 0x0400)

    @property
    def is_proxy(self) -> bool:
        return bool(self.value & 0x0800)

@dataclass
class GeoRecord:
    ip: str
    ip_from: int
    ip_to: int
    country: str
    region: str
    city: str
    isp: str
    asn: int
    latitude: float
    longitude: float
    flags: GeoFlags

    @property
    def range(self) -> str:
        f_ip = socket.inet_ntoa(struct.pack('!I', self.ip_from))
        t_ip = socket.inet_ntoa(struct.pack('!I', self.ip_to))
        return f"{f_ip} - {t_ip}"

class GrlgReader:
    """Zero-copy memory-mapped GRLG database reader."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._f = open(filepath, 'rb')
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        
        # Read magic and version
        magic, ver = struct.unpack('<4sH', self._mm[:6])
        if magic != b'GRLG':
            raise ValueError(f"Invalid GRLG magic: {magic}")
        self.version = ver
        
        if self.version == 3: # Full Unified (60 bytes header)
            hdr = struct.unpack('<4sHIHIIIIIIIIIIII', self._mm[:60])
            self.total_records = hdr[2]
            self.record_size = hdr[3]
            self.header_size = 60
            
            c_cnt, c_i_off, c_d_off, c_d_len = hdr[4], hdr[5], hdr[6], hdr[7]
            r_cnt, r_i_off, r_d_off, r_d_len = hdr[8], hdr[9], hdr[10], hdr[11]
            i_cnt, i_i_off, i_d_off, i_d_len = hdr[12], hdr[13], hdr[14], hdr[15]
            
            self._city_offsets = [struct.unpack('<I', self._mm[c_i_off + i*4:c_i_off + (i+1)*4])[0] for i in range(c_cnt)]
            self._city_blob = self._mm[c_d_off:c_d_off + c_d_len]
            
            self._region_offsets = [struct.unpack('<I', self._mm[r_i_off + i*4:r_i_off + (i+1)*4])[0] for i in range(r_cnt)]
            self._region_blob = self._mm[r_d_off:r_d_off + r_d_len]
            
            self._isp_offsets = [struct.unpack('<I', self._mm[i_i_off + i*4:i_i_off + (i+1)*4])[0] for i in range(i_cnt)]
            self._isp_blob = self._mm[i_d_off:i_d_off + i_d_len]
            
        elif self.version == 1: # Proxy Only (44 bytes header)
            hdr = struct.unpack('<4sHIHIIIIIIII', self._mm[:44])
            self.total_records = hdr[2]
            self.record_size = hdr[3]
            self.header_size = 44
            
            c_cnt, c_i_off, c_d_off, c_d_len = hdr[4], hdr[5], hdr[6], hdr[7]
            i_cnt, i_i_off, i_d_off, i_d_len = hdr[8], hdr[9], hdr[10], hdr[11]
            
            self._city_offsets = [struct.unpack('<I', self._mm[c_i_off + i*4:c_i_off + (i+1)*4])[0] for i in range(c_cnt)]
            self._city_blob = self._mm[c_d_off:c_d_off + c_d_len]
            self._region_offsets = []
            self._region_blob = b""
            
            self._isp_offsets = [struct.unpack('<I', self._mm[i_i_off + i*4:i_i_off + (i+1)*4])[0] for i in range(i_cnt)]
            self._isp_blob = self._mm[i_d_off:i_d_off + i_d_len]
            
        elif self.version == 2: # Geo Only (44 bytes header)
            hdr = struct.unpack('<4sHIHIIIIIIII', self._mm[:44])
            self.total_records = hdr[2]
            self.record_size = hdr[3]
            self.header_size = 44
            
            c_cnt, c_i_off, c_d_off, c_d_len = hdr[4], hdr[5], hdr[6], hdr[7]
            r_cnt, r_i_off, r_d_off, r_d_len = hdr[8], hdr[9], hdr[10], hdr[11]
            
            self._city_offsets = [struct.unpack('<I', self._mm[c_i_off + i*4:c_i_off + (i+1)*4])[0] for i in range(c_cnt)]
            self._city_blob = self._mm[c_d_off:c_d_off + c_d_len]
            
            self._region_offsets = [struct.unpack('<I', self._mm[r_i_off + i*4:r_i_off + (i+1)*4])[0] for i in range(r_cnt)]
            self._region_blob = self._mm[r_d_off:r_d_off + r_d_len]
            self._isp_offsets = []
            self._isp_blob = b""
        else:
            raise ValueError(f"Unsupported GRLG version: {self.version}")

    def _get_string(self, offsets: list, blob: bytes, idx: int) -> str:
        if idx >= len(offsets):
            return ""
        off = offsets[idx]
        end = blob.find(b'\x00', off)
        if end == -1: end = len(blob)
        return blob[off:end].decode('utf-8', errors='ignore')

    def close(self):
        if hasattr(self, '_mm') and self._mm:
            self._mm.close()
        if hasattr(self, '_f') and self._f:
            self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def lookup(self, ip: Union[str, int]) -> Optional[GeoRecord]:
        """Looks up an IPv4 address. Returns GeoRecord if found."""
        if isinstance(ip, str):
            target = struct.unpack('!I', socket.inet_aton(ip))[0]
            ip_str = ip
        else:
            target = ip
            ip_str = socket.inet_ntoa(struct.pack('!I', target))

        low = 0
        high = self.total_records - 1
        
        while low <= high:
            mid = (low + high) // 2
            offset = self.header_size + mid * self.record_size
            
            if self.version == 3: # Full Unified (28 bytes)
                ip_from, ip_to, city_idx, asn, cc, reg_idx, isp_idx, flags, lat, lon = struct.unpack(
                    '<IIII2sHHHhh', self._mm[offset:offset+28]
                )
            elif self.version == 1: # Proxy Only (20 bytes)
                ip_from, ip_to, asn, city_idx, isp_idx, cc, flags = struct.unpack(
                    '<IIIHH2sH', self._mm[offset:offset+20]
                )
                reg_idx, lat, lon = 0, 0, 0
            else: # Geo Only (20 bytes)
                ip_from, ip_to, city_idx, cc, reg_idx, lat, lon = struct.unpack(
                    '<III2sHhh', self._mm[offset:offset+20]
                )
                asn, isp_idx, flags = 0, 0, 0

            if target < ip_from:
                high = mid - 1
            elif target > ip_to:
                low = mid + 1
            else:
                return GeoRecord(
                    ip=ip_str,
                    ip_from=ip_from,
                    ip_to=ip_to,
                    country=cc.decode('ascii', errors='ignore'),
                    region=self._get_string(self._region_offsets, self._region_blob, reg_idx),
                    city=self._get_string(self._city_offsets, self._city_blob, city_idx),
                    isp=self._get_string(self._isp_offsets, self._isp_blob, isp_idx),
                    asn=asn,
                    latitude=lat / 100.0,
                    longitude=lon / 100.0,
                    flags=GeoFlags(flags)
                )

        return None
