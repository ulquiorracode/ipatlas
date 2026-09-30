# IPAtlas

[![CI](https://github.com/ulquiorracode/ipatlas/actions/workflows/ci.yml/badge.svg)](https://github.com/ulquiorracode/ipatlas/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ulquiorracode/ipatlas?color=blue&label=version)](https://github.com/ulquiorracode/ipatlas/releases)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Ultra-fast zero-copy binary GeoIP and Proxy/VPN threat database compiler, reader, and specification.

Designed for high-throughput network engines, game servers (GoldSrc, Source, Rust), packet filters, and microservices requiring sub-microsecond IP classification without external dependencies or heavy in-memory daemons.

## Features

- **Zero-Copy Memory-Mapped Access (`mmap`)**: Query directly from disk cache without allocating hundreds of megabytes on the heap.
- **Sub-Microsecond Lookups**: Strict $O(\log N)$ binary search over contiguous fixed-size records ($\le 23$ comparisons).
- **1D Streaming Interval Sweep**: Seamlessly merges disjoint Geolocation (IP2Location DB1-DB26) and Proxy Threat Intelligence (IP2Proxy PX1-PX12) into unified atomic IP ranges.
- **Universal Dataset Support**: Dynamic column detection for all IP2Location LITE/Commercial formats (DB1, DB3, DB5, DB11) and IP2Proxy (PX1 - PX12).
- **Profile ID Normalization**: 7.95 million ranges map onto ~160k unique profiles, shrinking binary size by **55.2%**.
- **Extreme Compression**: Zstandard (`.zst`) achieves **26.8x compression** (740 MB CSV down to **27.6 MB**).
- **Bitflag Threat Classification**: Single-cycle bitwise checks for Datacenter/Hosting, Residential ISP, Proxy, VPN, Tor/Botnet, Spam, and Crawlers.
- **Zero External Dependencies**: Pure Python implementation using only the standard library.

## Benchmarks & Datasets

Tested on raw IP2Location LITE DB5 and IP2Proxy LITE PX10 datasets:

| Database Mode | Source CSV | Binary (`.bin`) | Gzip (`.gz`) | Zstandard (`.zst`) | Ratio (vs .zst) | Records | Profiles |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Unified Full V4 (DB + PX)** | 740 MB | **95.9 MB** *(was 214 MB)* | **35.4 MB** | **27.6 MB** | **26.8x** | 7,946,419 | 159,501 |
| **Geo-Only (DB5)** | 280 MB | 57.7 MB | 18.8 MB | 13.9 MB | 20.1x | 2,999,603 | — |
| **Proxy-Only (PX10)** | 460 MB | 48.7 MB | 11.6 MB | 9.4 MB | 48.9x | 2,429,915 | — |

> [!NOTE]
> **Version 4 Profile Normalization**: In Unified Full mode, 7.95 million ranges map onto only 159,501 unique metadata profiles `(Country, City, Region, ASN, ISP, Flags, Lat, Lon)`. Each range is reduced from **28 bytes to 12 bytes**, shrinking the uncompressed zero-copy mmap binary by **55.2%** (from 214 MB to 95.9 MB).

## Installation

```sh
pip install .
```

Or run directly without installation:

```sh
python -m ipatlas.cli --help
```

## CLI Usage

### 1. Compile Datasets

Compile raw CSVs into a binary database and compressed `.bin.zst` distribution:

```sh
# Unified Full (Geo + Proxy/Threats, e.g. DB5 + PX10 or DB11 + PX12)
ipatlas compile --mode full \
  --geo IP2LOCATION-LITE-DB5.CSV \
  --proxy IP2PROXY-LITE-PX10.CSV \
  -o ipatlas_full.bin

# Fast Preset Compilation (Cascade Coalescing):
# - firewall: Country + ASN + Threat flags (~7.9 MB binary, ~2.5 MB .zst)
ipatlas compile --preset firewall --geo IP2LOCATION-LITE-DB5.CSV --proxy IP2PROXY-LITE-PX10.CSV -o ipatlas_firewall.bin

# - country: Pure Geo-Blocking Country-Only (~5.6 MB binary, ~1.2 MB .zst, 233x reduction!)
ipatlas compile --preset country --geo IP2LOCATION-LITE-DB5.CSV -o ipatlas_country.bin

# - city: Country + Region + City + Coordinates without threats (~38 MB binary)
ipatlas compile --preset city --geo IP2LOCATION-LITE-DB5.CSV -o ipatlas_city.bin

# Custom Feature Mask:
ipatlas compile --features country,asn,threats \
  --geo IP2LOCATION-LITE-DB5.CSV --proxy IP2PROXY-LITE-PX10.CSV -o custom.bin

# Proxy-Only
ipatlas compile --mode proxy --proxy IP2PROXY-LITE-PX10.CSV -o ipatlas_proxy.bin

# Geo-Only
ipatlas compile --mode geo --geo IP2LOCATION-LITE-DB5.CSV -o ipatlas_geo.bin
```

### 2. Lookup an IP Address

```sh
ipatlas lookup ipatlas_full.bin 8.8.8.8
```

Output:

```text
IP:          8.8.8.8
Range:       8.8.8.0 - 8.8.8.255
Country:     US
Region:      California
City:        Mountain View
Coordinates: 37.41, -122.08
ISP:         Google LLC
ASN:         AS15169
Flags:       0x809 (Proxy/Anonymizer | Datacenter | Commercial)
  Datacenter:  True
  Proxy / VPN: True
  Botnet:      False
  Spam:        False
  Mobile:      False
  Residential: False
Lookup Time: 0.65 µs
```

### 3. Inspect Database Metadata

```sh
ipatlas info ipatlas_full.bin
```

### 4. Benchmark Throughput

```sh
ipatlas benchmark ipatlas_full.bin -n 100000
```

## Python API

```python
from ipatlas import IpAtlasReader

with IpAtlasReader("ipatlas_full.bin") as reader:
    record = reader.lookup("1.1.1.1")
    if record:
        print(f"Country: {record.country}, City: {record.city}")
        print(f"Is Datacenter: {record.flags.is_datacenter}")
        print(f"Is Proxy/VPN:   {record.flags.is_proxy}")
        print(f"Is Botnet:      {record.flags.is_botnet}")
```

## Binary Format Specification

All multi-byte integers are stored in **Little-Endian** format (`<`).

### Full Unified Layout (Version 4 with Profile Normalization)

- **Header (68 bytes)**:
  - `magic` (4B): `b'ATLS'` (or legacy `b'GRLG'`)
  - `version` (2B): `0x0004`
  - `total_records` (4B): `uint32`
  - `record_size` (2B): `12`
  - `profile_count` (4B): `uint32` (e.g. 159,501)
  - `profile_offset` (4B): `uint32`
  - `city_count` (4B), `c_idx_off` (4B), `c_data_off` (4B), `c_data_len` (4B)
  - `reg_count` (4B), `r_idx_off` (4B), `r_data_off` (4B), `r_data_len` (4B)
  - `isp_count` (4B), `i_idx_off` (4B), `i_data_off` (4B), `i_data_len` (4B)

- **Range Record Structure (12 bytes)**:
  - `ip_from` (4B, `uint32`)
  - `ip_to` (4B, `uint32`)
  - `profile_id` (4B, `uint32`)

- **Profile Record Structure (20 bytes)**:
  - `city_idx` (4B, `uint32`)
  - `asn` (4B, `uint32`)
  - `country` (2B, `char[2]`)
  - `reg_idx` (2B, `uint16`)
  - `isp_idx` (2B, `uint16`)
  - `flags` (2B, `uint16`)
  - `lat_fixed` (2B, `int16` = `round(lat * 100)`)
  - `lon_fixed` (2B, `int16` = `round(lon * 100)`)

- **Flags Bitmask**:
  - `0x0001` — Datacenter / Hosting (`DCH`)
  - `0x0002` — Fixed Residential ISP (`ISP`)
  - `0x0004` — Mobile Carrier (`MOB`)
  - `0x0008` — Commercial Enterprise (`COM`)
  - `0x0010` — Organization (`ORG`)
  - `0x0020` — Government / Military (`GOV`)
  - `0x0040` — University / School (`EDU`)
  - `0x0080` — Content Delivery Network (`CDN`)
  - `0x0100` — Spam Source (`SPAM`)
  - `0x0200` — Port / Vulnerability Scanner (`SCANNER`)
  - `0x0400` — DDoS / Botnet Node (`BOTNET`)
  - `0x0800` — Proxy / VPN Anonymizer (`PROXY`)

## Data Attribution & License

This site or product includes IP2Location LITE data available from [https://lite.ip2location.com](https://lite.ip2location.com).

This project is licensed under the [MIT License](LICENSE).
