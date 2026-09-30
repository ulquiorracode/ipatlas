"""
GRLG Database Compiler.

Supports:
- Full Unified Database: DB5 (Geo) + PX10 (Proxy/Threats) with 1D streaming interval sweep.
- Proxy-Only Database: PX10 (Proxy, Datacenter, Botnet, ASN, ISP).
- Geo-Only Database: DB5 (Country, Region, City, Latitude, Longitude).
"""

import csv
import struct
import time
import os
import zlib
from typing import Optional, Callable

USAGE_FLAGS = {
    'DCH': 0x0001, # Datacenter / Web Hosting (VPN / Proxy / Bot origin)
    'ISP': 0x0002, # Fixed Residential ISP
    'MOB': 0x0004, # Mobile Carrier
    'COM': 0x0008, # Commercial Enterprise
    'ORG': 0x0010, # Organization
    'GOV': 0x0020, # Government / Military
    'MIL': 0x0020, # Government / Military
    'EDU': 0x0040, # University / School
    'LIB': 0x0040, # Library / Education
    'CDN': 0x0080, # Content Delivery Network
}

THREAT_FLAGS = {
    'SPAM':    0x0100, # Spam Source
    'SCANNER': 0x0200, # Port / Vulnerability Scanner
    'BOTNET':  0x0400, # DDoS / Botnet Node
}

PROXY_FLAG = 0x0800 # Proxy / Anonymizer

def parse_px_flags(usage_str: str, threat_str: str) -> int:
    flags = PROXY_FLAG
    for u in usage_str.split('/'):
        flags |= USAGE_FLAGS.get(u, 0)
    for t, mask in THREAT_FLAGS.items():
        if t in threat_str:
            flags |= mask
    return flags

def compile_database(
    mode: str,
    output_path: str,
    db5_path: Optional[str] = None,
    px10_path: Optional[str] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> dict:
    """Compiles CSV database into GRLG binary format and compressed archive."""
    log = progress_callback or print

    if mode == "full":
        if not db5_path or not px10_path:
            raise ValueError("mode='full' requires both db5_path and px10_path")
        return _compile_full(db5_path, px10_path, output_path, log)
    elif mode == "proxy":
        if not px10_path:
            raise ValueError("mode='proxy' requires px10_path")
        return _compile_proxy_only(px10_path, output_path, log)
    elif mode == "geo":
        if not db5_path:
            raise ValueError("mode='geo' requires db5_path")
        return _compile_geo_only(db5_path, output_path, log)
    else:
        raise ValueError(f"Unknown mode: {mode}. Choose 'full', 'proxy', or 'geo'.")

def _compile_full(db5_path: str, px10_path: str, bin_out_path: str, log: Callable) -> dict:
    start = time.time()
    log(f"Compiling Unified Full Database (DB5 + PX10)...")
    
    cities_map = {"": 0, "-": 0}
    cities_list = [""]
    regions_map = {"": 0, "-": 0}
    regions_list = [""]
    isps_map = {"": 0, "-": 0}
    isps_list = [""]
    
    def get_city_idx(name: str) -> int:
        if name not in cities_map:
            cities_map[name] = len(cities_list)
            cities_list.append(name)
        return cities_map[name]
        
    def get_region_idx(name: str) -> int:
        if name not in regions_map:
            regions_map[name] = len(regions_list)
            regions_list.append(name)
        return regions_map[name]
        
    def get_isp_idx(name: str) -> int:
        if name not in isps_map:
            isps_map[name] = len(isps_list)
            isps_list.append(name)
        return isps_map[name]

    def stream_db5():
        with open(db5_path, 'r', encoding='utf-8') as f:
            for row in csv.reader(f):
                ip_from = int(row[0])
                ip_to = int(row[1])
                cc = row[2][:2].encode('ascii', errors='ignore')
                if len(cc) < 2: cc = b"--"
                reg_idx = get_region_idx(row[4])
                city_idx = get_city_idx(row[5])
                try: lat = int(round(float(row[6]) * 100))
                except ValueError: lat = 0
                try: lon = int(round(float(row[7]) * 100))
                except ValueError: lon = 0
                yield (ip_from, ip_to, city_idx, cc, reg_idx, lat, lon)

    def stream_px10():
        with open(px10_path, 'r', encoding='utf-8') as f:
            for row in csv.reader(f):
                ip_from = int(row[0])
                ip_to = int(row[1])
                isp_idx = get_isp_idx(row[7])
                try: asn = int(row[10]) & 0xFFFFFFFF
                except ValueError: asn = 0
                flags = parse_px_flags(row[9], row[13])
                yield (ip_from, ip_to, isp_idx, asn, flags)

    db5_iter = stream_db5()
    px10_iter = stream_px10()
    
    cur_geo = next(db5_iter, None)
    cur_px = next(px10_iter, None)
    
    merged_records = []
    
    while cur_geo is not None:
        g_from, g_to, city_idx, cc, reg_idx, lat, lon = cur_geo
        
        while cur_px is not None and cur_px[1] < g_from:
            cur_px = next(px10_iter, None)
            
        if cur_px is None or cur_px[0] > g_to:
            merged_records.append((g_from, g_to, city_idx, 0, cc, reg_idx, 0, 0, lat, lon))
            cur_geo = next(db5_iter, None)
        else:
            p_from, p_to, isp_idx, asn, flags = cur_px
            
            if g_from < p_from:
                merged_records.append((g_from, p_from - 1, city_idx, 0, cc, reg_idx, 0, 0, lat, lon))
                g_from = p_from
                
            overlap_end = min(g_to, p_to)
            merged_records.append((g_from, overlap_end, city_idx, asn, cc, reg_idx, isp_idx, flags, lat, lon))
            
            if g_to == overlap_end:
                cur_geo = next(db5_iter, None)
                if p_to == overlap_end:
                    cur_px = next(px10_iter, None)
            else:
                cur_geo = (overlap_end + 1, g_to, city_idx, cc, reg_idx, lat, lon)
                cur_px = next(px10_iter, None)

    # Coalescing adjacent identical intervals
    coalesced = []
    prev = None
    for r in merged_records:
        if prev is not None and prev[1] + 1 == r[0] and prev[2:] == r[2:]:
            prev = (prev[0], r[1], *prev[2:])
        else:
            if prev is not None:
                coalesced.append(prev)
            prev = r
    if prev is not None:
        coalesced.append(prev)

    # Build Profile ID normalization dictionary
    prof_map = {}
    prof_list = []
    ranges_v4 = []
    
    for r in coalesced:
        ip_from, ip_to, city_idx, asn, cc, reg_idx, isp_idx, flags, lat, lon = r
        p_key = (city_idx, asn, cc, reg_idx, isp_idx, flags, lat, lon)
        if p_key not in prof_map:
            prof_map[p_key] = len(prof_list)
            prof_list.append(p_key)
        prof_id = prof_map[p_key]
        ranges_v4.append((ip_from, ip_to, prof_id))

    # Serialize string blobs
    cities_blob = bytearray()
    city_offsets = []
    for c in cities_list:
        city_offsets.append(len(cities_blob))
        cities_blob.extend(c.encode('utf-8'))
        cities_blob.append(0)
        
    regions_blob = bytearray()
    region_offsets = []
    for r in regions_list:
        region_offsets.append(len(regions_blob))
        regions_blob.extend(r.encode('utf-8'))
        regions_blob.append(0)
        
    isps_blob = bytearray()
    isp_offsets = []
    for isp in isps_list:
        isp_offsets.append(len(isps_blob))
        isps_blob.extend(isp.encode('utf-8'))
        isps_blob.append(0)
        
    header_size = 68 # 68 bytes header (with prof_count, prof_offset)
    records_size = len(ranges_v4) * 12 # 12 bytes per IP range
    prof_size = len(prof_list) * 20 # 20 bytes per unique profile
    
    prof_offset = header_size + records_size
    c_idx_off = prof_offset + prof_size
    c_idx_len = len(city_offsets) * 4
    c_data_off = c_idx_off + c_idx_len
    c_data_len = len(cities_blob)
    
    r_idx_off = c_data_off + c_data_len
    r_idx_len = len(region_offsets) * 4
    r_data_off = r_idx_off + r_idx_len
    r_data_len = len(regions_blob)
    
    i_idx_off = r_data_off + r_data_len
    i_idx_len = len(isp_offsets) * 4
    i_data_off = i_idx_off + i_idx_len
    i_data_len = len(isps_blob)
    
    os.makedirs(os.path.dirname(os.path.abspath(bin_out_path)), exist_ok=True)
    with open(bin_out_path, 'wb') as f:
        f.write(struct.pack(
            '<4sHIHIIIIIIIIIIIIII',
            b'GRLG',
            4, # version 4 = Full Unified with Profile ID Normalization
            len(ranges_v4),
            12, # record size = 12 bytes
            len(prof_list),
            prof_offset,
            len(cities_list),
            c_idx_off, c_data_off, c_data_len,
            len(regions_list),
            r_idx_off, r_data_off, r_data_len,
            len(isps_list),
            i_idx_off, i_data_off, i_data_len
        ))
        for r in ranges_v4:
            f.write(struct.pack('<III', r[0], r[1], r[2]))
            
        for p in prof_list:
            city_idx, asn, cc, reg_idx, isp_idx, flags, lat, lon = p
            f.write(struct.pack('<II2sHHHhh', city_idx, asn, cc, reg_idx, isp_idx, flags, lat, lon))
            
        for off in city_offsets: f.write(struct.pack('<I', off))
        f.write(cities_blob)
        for off in region_offsets: f.write(struct.pack('<I', off))
        f.write(regions_blob)
        for off in isp_offsets: f.write(struct.pack('<I', off))
        f.write(isps_blob)
        
    raw_size = os.path.getsize(bin_out_path)
    gz_path = bin_out_path + ".gz"
    with open(bin_out_path, 'rb') as f_in, open(gz_path, 'wb') as f_out:
        compressed = zlib.compress(f_in.read(), level=9)
        f_out.write(compressed)
    gz_size = os.path.getsize(gz_path)
    
    # Try compressing with zstd if available
    zst_size = None
    zst_path = bin_out_path + ".zst"
    try:
        import subprocess
        res = subprocess.run(['zstd', '-19', '-f', bin_out_path, '-o', zst_path], capture_output=True)
        if res.returncode == 0 and os.path.exists(zst_path):
            zst_size = os.path.getsize(zst_path)
    except Exception:
        zst_size = None

    total_csv_size = os.path.getsize(db5_path) + os.path.getsize(px10_path)
    
    elapsed = time.time() - start
    stats = {
        "mode": "full",
        "records": len(ranges_v4),
        "profiles": len(prof_list),
        "cities": len(cities_list),
        "regions": len(regions_list),
        "isps": len(isps_list),
        "raw_size": raw_size,
        "gz_size": gz_size,
        "zst_size": zst_size,
        "csv_size": total_csv_size,
        "compression_ratio": round(total_csv_size / gz_size, 2),
        "zst_ratio": round(total_csv_size / zst_size, 2) if zst_size else None,
        "elapsed_seconds": round(elapsed, 2)
    }
    zst_msg = f" | ZST: {zst_size/(1024*1024):.1f} MB ({stats['zst_ratio']}x)" if zst_size else ""
    log(f"Compiled {len(ranges_v4):,} intervals ({len(prof_list):,} profiles) in {elapsed:.2f}s | Binary: {raw_size/(1024*1024):.1f} MB | GZ: {gz_size/(1024*1024):.1f} MB ({stats['compression_ratio']}x){zst_msg}")
    return stats

def _compile_proxy_only(px10_path: str, bin_out_path: str, log: Callable) -> dict:
    start = time.time()
    log(f"Compiling Proxy-Only Database (PX10)...")
    
    cities_map = {"": 0, "-": 0}
    cities_list = [""]
    isps_map = {"": 0, "-": 0}
    isps_list = [""]
    records = []
    
    prev_from = None
    prev_to = None
    prev_meta = None
    
    with open(px10_path, 'r', encoding='utf-8') as f:
        for row in csv.reader(f):
            ip_from = int(row[0])
            ip_to = int(row[1])
            cc = row[3][:2].encode('ascii', errors='ignore')
            if len(cc) < 2: cc = b"--"
            city_str = row[6]
            isp_str = row[7]
            
            if city_str not in cities_map:
                cities_map[city_str] = len(cities_list)
                cities_list.append(city_str)
            city_idx = cities_map[city_str]
            
            if isp_str not in isps_map:
                isps_map[isp_str] = len(isps_list)
                isps_list.append(isp_str)
            isp_idx = isps_map[isp_str]
            
            try: asn = int(row[10]) & 0xFFFFFFFF
            except ValueError: asn = 0
            flags = parse_px_flags(row[9], row[13])
            
            meta = (asn, city_idx, isp_idx, cc, flags)
            if prev_meta is not None and prev_to + 1 == ip_from and meta == prev_meta:
                prev_to = ip_to
            else:
                if prev_meta is not None:
                    records.append((prev_from, prev_to, *prev_meta))
                prev_from = ip_from
                prev_to = ip_to
                prev_meta = meta
                
    if prev_meta is not None:
        records.append((prev_from, prev_to, *prev_meta))

    cities_blob = bytearray()
    city_offsets = []
    for c in cities_list:
        city_offsets.append(len(cities_blob))
        cities_blob.extend(c.encode('utf-8'))
        cities_blob.append(0)
        
    isps_blob = bytearray()
    isp_offsets = []
    for isp in isps_list:
        isp_offsets.append(len(isps_blob))
        isps_blob.extend(isp.encode('utf-8'))
        isps_blob.append(0)
        
    header_size = 44
    records_size = len(records) * 20
    
    c_idx_off = header_size + records_size
    c_idx_len = len(city_offsets) * 4
    c_data_off = c_idx_off + c_idx_len
    c_data_len = len(cities_blob)
    
    i_idx_off = c_data_off + c_data_len
    i_idx_len = len(isp_offsets) * 4
    i_data_off = i_idx_off + i_idx_len
    i_data_len = len(isps_blob)
    
    os.makedirs(os.path.dirname(os.path.abspath(bin_out_path)), exist_ok=True)
    with open(bin_out_path, 'wb') as f:
        f.write(struct.pack(
            '<4sHIHIIIIIIII',
            b'GRLG',
            1, # version 1 = Proxy Only
            len(records),
            20,
            len(cities_list),
            c_idx_off, c_data_off, c_data_len,
            len(isps_list),
            i_idx_off, i_data_off, i_data_len
        ))
        for r in records:
            ip_from, ip_to, asn, city_idx, isp_idx, cc, flags = r
            f.write(struct.pack('<IIIHH2sH', ip_from, ip_to, asn, city_idx, isp_idx, cc, flags))
        for off in city_offsets: f.write(struct.pack('<I', off))
        f.write(cities_blob)
        for off in isp_offsets: f.write(struct.pack('<I', off))
        f.write(isps_blob)
        
    raw_size = os.path.getsize(bin_out_path)
    gz_path = bin_out_path + ".gz"
    with open(bin_out_path, 'rb') as f_in, open(gz_path, 'wb') as f_out:
        compressed = zlib.compress(f_in.read(), level=9)
        f_out.write(compressed)
    gz_size = os.path.getsize(gz_path)
    csv_size = os.path.getsize(px10_path)
    
    elapsed = time.time() - start
    stats = {
        "mode": "proxy",
        "records": len(records),
        "cities": len(cities_list),
        "isps": len(isps_list),
        "raw_size": raw_size,
        "gz_size": gz_size,
        "csv_size": csv_size,
        "compression_ratio": round(csv_size / gz_size, 2),
        "elapsed_seconds": round(elapsed, 2)
    }
    log(f"Compiled {len(records):,} proxy records in {elapsed:.2f}s | Binary: {raw_size/(1024*1024):.1f} MB | GZ: {gz_size/(1024*1024):.1f} MB ({stats['compression_ratio']}x)")
    return stats

def _compile_geo_only(db5_path: str, bin_out_path: str, log: Callable) -> dict:
    start = time.time()
    log(f"Compiling Geo-Only Database (DB5)...")
    
    cities_map = {"": 0, "-": 0}
    cities_list = [""]
    regions_map = {"": 0, "-": 0}
    regions_list = [""]
    records = []
    
    prev_from = None
    prev_to = None
    prev_meta = None
    
    with open(db5_path, 'r', encoding='utf-8') as f:
        for row in csv.reader(f):
            ip_from = int(row[0])
            ip_to = int(row[1])
            cc = row[2][:2].encode('ascii', errors='ignore')
            if len(cc) < 2: cc = b"--"
            reg_str = row[4]
            city_str = row[5]
            
            try: lat = int(round(float(row[6]) * 100))
            except ValueError: lat = 0
            try: lon = int(round(float(row[7]) * 100))
            except ValueError: lon = 0
            
            if city_str not in cities_map:
                cities_map[city_str] = len(cities_list)
                cities_list.append(city_str)
            city_idx = cities_map[city_str]
            
            if reg_str not in regions_map:
                regions_map[reg_str] = len(regions_list)
                regions_list.append(reg_str)
            reg_idx = regions_map[reg_str]
            
            meta = (city_idx, cc, reg_idx, lat, lon)
            if prev_meta is not None and prev_to + 1 == ip_from and meta == prev_meta:
                prev_to = ip_to
            else:
                if prev_meta is not None:
                    records.append((prev_from, prev_to, *prev_meta))
                prev_from = ip_from
                prev_to = ip_to
                prev_meta = meta
                
    if prev_meta is not None:
        records.append((prev_from, prev_to, *prev_meta))

    cities_blob = bytearray()
    city_offsets = []
    for c in cities_list:
        city_offsets.append(len(cities_blob))
        cities_blob.extend(c.encode('utf-8'))
        cities_blob.append(0)
        
    regions_blob = bytearray()
    region_offsets = []
    for r in regions_list:
        region_offsets.append(len(regions_blob))
        regions_blob.extend(r.encode('utf-8'))
        regions_blob.append(0)
        
    header_size = 44
    records_size = len(records) * 20
    
    c_idx_off = header_size + records_size
    c_idx_len = len(city_offsets) * 4
    c_data_off = c_idx_off + c_idx_len
    c_data_len = len(cities_blob)
    
    r_idx_off = c_data_off + c_data_len
    r_idx_len = len(region_offsets) * 4
    r_data_off = r_idx_off + r_idx_len
    r_data_len = len(regions_blob)
    
    os.makedirs(os.path.dirname(os.path.abspath(bin_out_path)), exist_ok=True)
    with open(bin_out_path, 'wb') as f:
        f.write(struct.pack(
            '<4sHIHIIIIIIII',
            b'GRLG',
            2, # version 2 = Geo Only
            len(records),
            20,
            len(cities_list),
            c_idx_off, c_data_off, c_data_len,
            len(regions_list),
            r_idx_off, r_data_off, r_data_len
        ))
        for r in records:
            ip_from, ip_to, city_idx, cc, reg_idx, lat, lon = r
            f.write(struct.pack('<III2sHhh', ip_from, ip_to, city_idx, cc, reg_idx, lat, lon))
        for off in city_offsets: f.write(struct.pack('<I', off))
        f.write(cities_blob)
        for off in region_offsets: f.write(struct.pack('<I', off))
        f.write(regions_blob)
        
    raw_size = os.path.getsize(bin_out_path)
    gz_path = bin_out_path + ".gz"
    with open(bin_out_path, 'rb') as f_in, open(gz_path, 'wb') as f_out:
        compressed = zlib.compress(f_in.read(), level=9)
        f_out.write(compressed)
    gz_size = os.path.getsize(gz_path)
    csv_size = os.path.getsize(db5_path)
    
    elapsed = time.time() - start
    stats = {
        "mode": "geo",
        "records": len(records),
        "cities": len(cities_list),
        "regions": len(regions_list),
        "raw_size": raw_size,
        "gz_size": gz_size,
        "csv_size": csv_size,
        "compression_ratio": round(csv_size / gz_size, 2),
        "elapsed_seconds": round(elapsed, 2)
    }
    log(f"Compiled {len(records):,} geo records in {elapsed:.2f}s | Binary: {raw_size/(1024*1024):.1f} MB | GZ: {gz_size/(1024*1024):.1f} MB ({stats['compression_ratio']}x)")
    return stats
