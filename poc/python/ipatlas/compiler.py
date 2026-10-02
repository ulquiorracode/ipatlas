"""
IPAtlas Database Compiler.

Ultra-fast zero-copy binary GeoIP and Proxy/VPN threat database compiler.
Supports arbitrary feature masks, presets, and any IP2Location DB / IP2Proxy PX datasets.
"""

import csv
import struct
import time
import os
import zlib
import subprocess
from typing import Optional, Callable, Dict

MAGIC = b'ATLS'

# Feature bitmasks
FEATURE_COUNTRY = 0x0001
FEATURE_REGION  = 0x0002
FEATURE_CITY    = 0x0004
FEATURE_COORDS  = 0x0008
FEATURE_ISP     = 0x0010
FEATURE_ASN     = 0x0020
FEATURE_THREATS = 0x0040

ALL_FEATURES = (
    FEATURE_COUNTRY |
    FEATURE_REGION  |
    FEATURE_CITY    |
    FEATURE_COORDS  |
    FEATURE_ISP     |
    FEATURE_ASN     |
    FEATURE_THREATS
)

PRESETS: Dict[str, int] = {
    "full": ALL_FEATURES,
    "city": FEATURE_COUNTRY | FEATURE_REGION | FEATURE_CITY | FEATURE_COORDS,
    "firewall": FEATURE_COUNTRY | FEATURE_ASN | FEATURE_THREATS,
    "country": FEATURE_COUNTRY,
    "threats": FEATURE_ASN | FEATURE_THREATS,
}

FEATURE_NAMES = {
    "country": FEATURE_COUNTRY,
    "region": FEATURE_REGION,
    "city": FEATURE_CITY,
    "coords": FEATURE_COORDS,
    "latlon": FEATURE_COORDS,
    "isp": FEATURE_ISP,
    "asn": FEATURE_ASN,
    "threats": FEATURE_THREATS,
    "proxy": FEATURE_THREATS,
}

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

def parse_features(features_str: Optional[str] = None, preset: Optional[str] = None) -> int:
    """Resolves features bitmask from preset name or comma-separated list of feature names."""
    if preset:
        preset_lower = preset.strip().lower()
        if preset_lower in PRESETS:
            return PRESETS[preset_lower]
        raise ValueError(f"Unknown preset: '{preset}'. Available presets: {list(PRESETS.keys())}")
    
    if not features_str:
        return ALL_FEATURES

    mask = 0
    for item in features_str.split(','):
        name = item.strip().lower()
        if not name:
            continue
        if name in FEATURE_NAMES:
            mask |= FEATURE_NAMES[name]
        elif name in PRESETS:
            mask |= PRESETS[name]
        else:
            raise ValueError(f"Unknown feature or preset: '{name}'. Available: {list(FEATURE_NAMES.keys())}")
    return mask

def parse_px_flags(usage_str: str, threat_str: str) -> int:
    flags = PROXY_FLAG
    if usage_str:
        for u in usage_str.split('/'):
            flags |= USAGE_FLAGS.get(u, 0)
    if threat_str:
        for t, mask in THREAT_FLAGS.items():
            if t in threat_str:
                flags |= mask
    return flags

def _safe_float_latlon(val: str) -> int:
    try:
        return int(round(float(val) * 100))
    except (ValueError, TypeError):
        return 0

def _safe_asn(val: str) -> int:
    try:
        if val.upper().startswith("AS"):
            val = val[2:]
        return int(val) & 0xFFFFFFFF
    except (ValueError, TypeError):
        return 0

def compile_database(
    mode: str,
    output_path: str,
    db_path: Optional[str] = None,
    px_path: Optional[str] = None,
    preset: Optional[str] = None,
    features: Optional[str] = None,
    # Backwards compatibility kwargs
    db5_path: Optional[str] = None,
    px10_path: Optional[str] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> dict:
    """Compiles IP2Location and IP2Proxy CSV datasets into IPAtlas binary and archives."""
    log = progress_callback or print
    geo_csv = db_path or db5_path
    proxy_csv = px_path or px10_path

    # Determine feature mask
    if preset or features:
        feature_mask = parse_features(features_str=features, preset=preset)
    elif mode == "proxy":
        feature_mask = FEATURE_COUNTRY | FEATURE_CITY | FEATURE_ISP | FEATURE_ASN | FEATURE_THREATS
    elif mode == "geo":
        feature_mask = FEATURE_COUNTRY | FEATURE_REGION | FEATURE_CITY | FEATURE_COORDS
    else:
        feature_mask = ALL_FEATURES

    if mode == "full" or preset:
        # Full mode or preset-driven: requires geo_csv if geo features needed, px_csv if threat features needed
        need_geo = bool(feature_mask & (FEATURE_COUNTRY | FEATURE_REGION | FEATURE_CITY | FEATURE_COORDS))
        need_px = bool(feature_mask & (FEATURE_ISP | FEATURE_ASN | FEATURE_THREATS))
        
        if need_geo and not geo_csv:
            raise ValueError(f"Feature mask requires GeoIP dataset (--geo), but none provided.")
        if need_px and not proxy_csv:
            if not geo_csv:
                raise ValueError("Requires at least --geo or --proxy dataset.")
            # If only geo_csv provided but need_px was requested, we gracefully proceed with threats disabled
            need_px = False
            feature_mask &= ~(FEATURE_ISP | FEATURE_ASN | FEATURE_THREATS)

        if geo_csv and proxy_csv:
            return _compile_full(geo_csv, proxy_csv, output_path, feature_mask, log)
        elif need_px and proxy_csv:
            return _compile_proxy_only(proxy_csv, output_path, feature_mask, log)
        elif geo_csv:
            return _compile_geo_only(geo_csv, output_path, feature_mask, log)
        else:
            raise ValueError("No valid dataset combination found for compilation.")
    elif mode == "proxy":
        if not proxy_csv:
            raise ValueError("mode='proxy' requires px_path (or px10_path)")
        return _compile_proxy_only(proxy_csv, output_path, feature_mask, log)
    elif mode == "geo":
        if not geo_csv:
            raise ValueError("mode='geo' requires db_path (or db5_path)")
        return _compile_geo_only(geo_csv, output_path, feature_mask, log)
    else:
        raise ValueError(f"Unknown mode: {mode}. Choose 'full', 'proxy', or 'geo'.")

def _compile_full(geo_path: str, px_path: str, bin_out_path: str, feature_mask: int, log: Callable) -> dict:
    start = time.time()
    log(f"Compiling Unified Database with feature mask: {hex(feature_mask)}...")
    
    has_country = bool(feature_mask & FEATURE_COUNTRY)
    has_region = bool(feature_mask & FEATURE_REGION)
    has_city = bool(feature_mask & FEATURE_CITY)
    has_coords = bool(feature_mask & FEATURE_COORDS)
    has_isp = bool(feature_mask & FEATURE_ISP)
    has_asn = bool(feature_mask & FEATURE_ASN)
    has_threats = bool(feature_mask & FEATURE_THREATS)

    cities_map = {"": 0, "-": 0}
    cities_list = [""]
    regions_map = {"": 0, "-": 0}
    regions_list = [""]
    isps_map = {"": 0, "-": 0}
    isps_list = [""]
    
    def get_city_idx(name: str) -> int:
        if not has_city or not name: return 0
        if name not in cities_map:
            cities_map[name] = len(cities_list)
            cities_list.append(name)
        return cities_map[name]
        
    def get_region_idx(name: str) -> int:
        if not has_region or not name: return 0
        if name not in regions_map:
            regions_map[name] = len(regions_list)
            regions_list.append(name)
        return regions_map[name]
        
    def get_isp_idx(name: str) -> int:
        if not has_isp or not name: return 0
        if name not in isps_map:
            isps_map[name] = len(isps_list)
            isps_list.append(name)
        return isps_map[name]

    def stream_geo():
        with open(geo_path, 'r', encoding='utf-8') as f:
            for row in csv.reader(f):
                if not row or not row[0].isdigit():
                    continue
                ip_from = int(row[0])
                ip_to = int(row[1])
                cc = row[2][:2].encode('ascii', errors='ignore') if (has_country and len(row) > 2) else b"--"
                if len(cc) < 2: cc = b"--"
                
                reg_idx = get_region_idx(row[4]) if (has_region and len(row) > 4) else 0
                city_idx = get_city_idx(row[5]) if (has_city and len(row) > 5) else 0
                lat = _safe_float_latlon(row[6]) if (has_coords and len(row) > 6) else 0
                lon = _safe_float_latlon(row[7]) if (has_coords and len(row) > 7) else 0
                
                yield (ip_from, ip_to, city_idx, cc, reg_idx, lat, lon)

    def stream_px():
        with open(px_path, 'r', encoding='utf-8') as f:
            for row in csv.reader(f):
                if not row or not row[0].isdigit():
                    continue
                ip_from = int(row[0])
                ip_to = int(row[1])
                isp_str = row[7] if (has_isp and len(row) > 7) else ""
                isp_idx = get_isp_idx(isp_str)
                asn = _safe_asn(row[10]) if (has_asn and len(row) > 10) else 0
                usage = row[9] if len(row) > 9 else ""
                threat = row[13] if len(row) > 13 else ""
                flags = parse_px_flags(usage, threat) if has_threats else 0
                yield (ip_from, ip_to, isp_idx, asn, flags)

    geo_iter = stream_geo()
    px_iter = stream_px()
    
    cur_geo = next(geo_iter, None)
    cur_px = next(px_iter, None)
    
    merged_records = []
    
    while cur_geo is not None:
        g_from, g_to, city_idx, cc, reg_idx, lat, lon = cur_geo
        
        while cur_px is not None and cur_px[1] < g_from:
            cur_px = next(px_iter, None)
            
        if cur_px is None or cur_px[0] > g_to:
            merged_records.append((g_from, g_to, city_idx, 0, cc, reg_idx, 0, 0, lat, lon))
            cur_geo = next(geo_iter, None)
        else:
            p_from, p_to, isp_idx, asn, flags = cur_px
            
            if g_from < p_from:
                merged_records.append((g_from, p_from - 1, city_idx, 0, cc, reg_idx, 0, 0, lat, lon))
                g_from = p_from
                
            overlap_end = min(g_to, p_to)
            merged_records.append((g_from, overlap_end, city_idx, asn, cc, reg_idx, isp_idx, flags, lat, lon))
            
            if g_to == overlap_end:
                cur_geo = next(geo_iter, None)
                if p_to == overlap_end:
                    cur_px = next(px_iter, None)
            else:
                cur_geo = (overlap_end + 1, g_to, city_idx, cc, reg_idx, lat, lon)
                cur_px = next(px_iter, None)

    # Coalescing adjacent identical intervals (Feature-Mask sensitive!)
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
    if has_city:
        for c in cities_list:
            city_offsets.append(len(cities_blob))
            cities_blob.extend(c.encode('utf-8'))
            cities_blob.append(0)
        
    regions_blob = bytearray()
    region_offsets = []
    if has_region:
        for r in regions_list:
            region_offsets.append(len(regions_blob))
            regions_blob.extend(r.encode('utf-8'))
            regions_blob.append(0)
        
    isps_blob = bytearray()
    isp_offsets = []
    if has_isp:
        for isp in isps_list:
            isp_offsets.append(len(isps_blob))
            isps_blob.extend(isp.encode('utf-8'))
            isps_blob.append(0)
        
    header_size = 68
    records_size = len(ranges_v4) * 12
    prof_size = len(prof_list) * 20
    
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
            MAGIC,
            4, # version 4
            len(ranges_v4),
            12, # record size = 12 bytes
            len(prof_list),
            prof_offset,
            len(city_offsets),
            c_idx_off, c_data_off, c_data_len,
            len(region_offsets),
            r_idx_off, r_data_off, r_data_len,
            len(isp_offsets),
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
    
    zst_size = None
    zst_path = bin_out_path + ".zst"
    try:
        res = subprocess.run(['zstd', '-19', '-f', bin_out_path, '-o', zst_path], capture_output=True)
        if res.returncode == 0 and os.path.exists(zst_path):
            zst_size = os.path.getsize(zst_path)
    except Exception:
        zst_size = None

    total_csv_size = os.path.getsize(geo_path) + os.path.getsize(px_path)
    
    elapsed = time.time() - start
    stats = {
        "mode": "full",
        "features": feature_mask,
        "records": len(ranges_v4),
        "profiles": len(prof_list),
        "cities": len(city_offsets),
        "regions": len(region_offsets),
        "isps": len(isp_offsets),
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

def _compile_proxy_only(px_path: str, bin_out_path: str, feature_mask: int, log: Callable) -> dict:
    start = time.time()
    log("Compiling Proxy-Only Database...")
    
    has_country = bool(feature_mask & FEATURE_COUNTRY)
    has_city = bool(feature_mask & FEATURE_CITY)
    has_isp = bool(feature_mask & FEATURE_ISP)
    has_asn = bool(feature_mask & FEATURE_ASN)
    has_threats = bool(feature_mask & FEATURE_THREATS)

    cities_map = {"": 0, "-": 0}
    cities_list = [""]
    isps_map = {"": 0, "-": 0}
    isps_list = [""]
    records = []
    
    prev_from = None
    prev_to = None
    prev_meta = None
    
    with open(px_path, 'r', encoding='utf-8') as f:
        for row in csv.reader(f):
            if not row or not row[0].isdigit():
                continue
            ip_from = int(row[0])
            ip_to = int(row[1])
            cc = row[3][:2].encode('ascii', errors='ignore') if (has_country and len(row) > 3) else b"--"
            if len(cc) < 2: cc = b"--"
            city_str = row[6] if (has_city and len(row) > 6) else ""
            isp_str = row[7] if (has_isp and len(row) > 7) else ""
            
            city_idx = 0
            if has_city and city_str:
                if city_str not in cities_map:
                    cities_map[city_str] = len(cities_list)
                    cities_list.append(city_str)
                city_idx = cities_map[city_str]
            
            isp_idx = 0
            if has_isp and isp_str:
                if isp_str not in isps_map:
                    isps_map[isp_str] = len(isps_list)
                    isps_list.append(isp_str)
                isp_idx = isps_map[isp_str]
            
            asn = _safe_asn(row[10]) if (has_asn and len(row) > 10) else 0
            usage = row[9] if len(row) > 9 else ""
            threat = row[13] if len(row) > 13 else ""
            flags = parse_px_flags(usage, threat) if has_threats else 0
            
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
    if has_city:
        for c in cities_list:
            city_offsets.append(len(cities_blob))
            cities_blob.extend(c.encode('utf-8'))
            cities_blob.append(0)
        
    isps_blob = bytearray()
    isp_offsets = []
    if has_isp:
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
            MAGIC,
            1, # version 1 = Proxy Only
            len(records),
            20,
            len(city_offsets),
            c_idx_off, c_data_off, c_data_len,
            len(isp_offsets),
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
    
    zst_size = None
    zst_path = bin_out_path + ".zst"
    try:
        res = subprocess.run(['zstd', '-19', '-f', bin_out_path, '-o', zst_path], capture_output=True)
        if res.returncode == 0 and os.path.exists(zst_path):
            zst_size = os.path.getsize(zst_path)
    except Exception:
        zst_size = None

    csv_size = os.path.getsize(px_path)
    elapsed = time.time() - start
    stats = {
        "mode": "proxy",
        "features": feature_mask,
        "records": len(records),
        "cities": len(city_offsets),
        "isps": len(isp_offsets),
        "raw_size": raw_size,
        "gz_size": gz_size,
        "zst_size": zst_size,
        "csv_size": csv_size,
        "compression_ratio": round(csv_size / gz_size, 2),
        "zst_ratio": round(csv_size / zst_size, 2) if zst_size else None,
        "elapsed_seconds": round(elapsed, 2)
    }
    zst_msg = f" | ZST: {zst_size/(1024*1024):.1f} MB ({stats['zst_ratio']}x)" if zst_size else ""
    log(f"Compiled {len(records):,} proxy records in {elapsed:.2f}s | Binary: {raw_size/(1024*1024):.1f} MB | GZ: {gz_size/(1024*1024):.1f} MB ({stats['compression_ratio']}x){zst_msg}")
    return stats

def _compile_geo_only(geo_path: str, bin_out_path: str, feature_mask: int, log: Callable) -> dict:
    start = time.time()
    log("Compiling Geo-Only Database...")
    
    has_country = bool(feature_mask & FEATURE_COUNTRY)
    has_region = bool(feature_mask & FEATURE_REGION)
    has_city = bool(feature_mask & FEATURE_CITY)
    has_coords = bool(feature_mask & FEATURE_COORDS)

    cities_map = {"": 0, "-": 0}
    cities_list = [""]
    regions_map = {"": 0, "-": 0}
    regions_list = [""]
    records = []
    
    prev_from = None
    prev_to = None
    prev_meta = None
    
    with open(geo_path, 'r', encoding='utf-8') as f:
        for row in csv.reader(f):
            if not row or not row[0].isdigit():
                continue
            ip_from = int(row[0])
            ip_to = int(row[1])
            cc = row[2][:2].encode('ascii', errors='ignore') if (has_country and len(row) > 2) else b"--"
            if len(cc) < 2: cc = b"--"
            reg_str = row[4] if (has_region and len(row) > 4) else ""
            city_str = row[5] if (has_city and len(row) > 5) else ""
            lat = _safe_float_latlon(row[6]) if (has_coords and len(row) > 6) else 0
            lon = _safe_float_latlon(row[7]) if (has_coords and len(row) > 7) else 0
            
            city_idx = 0
            if has_city and city_str:
                if city_str not in cities_map:
                    cities_map[city_str] = len(cities_list)
                    cities_list.append(city_str)
                city_idx = cities_map[city_str]
            
            reg_idx = 0
            if has_region and reg_str:
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
    if has_city:
        for c in cities_list:
            city_offsets.append(len(cities_blob))
            cities_blob.extend(c.encode('utf-8'))
            cities_blob.append(0)
        
    regions_blob = bytearray()
    region_offsets = []
    if has_region:
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
            MAGIC,
            2, # version 2 = Geo Only
            len(records),
            20,
            len(city_offsets),
            c_idx_off, c_data_off, c_data_len,
            len(region_offsets),
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
    
    zst_size = None
    zst_path = bin_out_path + ".zst"
    try:
        res = subprocess.run(['zstd', '-19', '-f', bin_out_path, '-o', zst_path], capture_output=True)
        if res.returncode == 0 and os.path.exists(zst_path):
            zst_size = os.path.getsize(zst_path)
    except Exception:
        zst_size = None

    csv_size = os.path.getsize(geo_path)
    elapsed = time.time() - start
    stats = {
        "mode": "geo",
        "features": feature_mask,
        "records": len(records),
        "cities": len(city_offsets),
        "regions": len(region_offsets),
        "raw_size": raw_size,
        "gz_size": gz_size,
        "zst_size": zst_size,
        "csv_size": csv_size,
        "compression_ratio": round(csv_size / gz_size, 2),
        "zst_ratio": round(csv_size / zst_size, 2) if zst_size else None,
        "elapsed_seconds": round(elapsed, 2)
    }
    zst_msg = f" | ZST: {zst_size/(1024*1024):.1f} MB ({stats['zst_ratio']}x)" if zst_size else ""
    log(f"Compiled {len(records):,} geo records in {elapsed:.2f}s | Binary: {raw_size/(1024*1024):.1f} MB | GZ: {gz_size/(1024*1024):.1f} MB ({stats['compression_ratio']}x){zst_msg}")
    return stats
