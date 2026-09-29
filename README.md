# grlg-geo

[![CI](https://github.com/ulquiorracode/grlg-geo/actions/workflows/ci.yml/badge.svg)](https://github.com/ulquiorracode/grlg-geo/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Ultra-fast zero-copy binary GeoIP and Proxy/VPN threat database compiler, reader, and specification.

Designed for high-throughput network engines, game servers (GoldSrc, Source, Rust), packet filters, and microservices requiring sub-microsecond IP classification without external dependencies or heavy in-memory daemons.

---

## Features

- **Zero-Copy Memory-Mapped Access (`mmap`)**: Query directly from disk cache without allocating hundreds of megabytes on the heap.
- **Sub-Microsecond Lookups**: Strict $O(\log N)$ binary search over contiguous fixed-size records ($\le 23$ comparisons).
- **1D Streaming Interval Sweep**: Seamlessly merges disjoint Geolocation (IP2Location DB5) and Proxy Threat Intelligence (IP2Proxy PX10) into unified atomic IP ranges.
- **Extreme Compression**: Deduplicated string pools and bitflag packing compress 775 MB of raw CSV datasets down to **43.8 MB** `.gz` (**17.7x reduction**).
- **Bitflag Threat Classification**: Single-cycle bitwise checks for Datacenter/Hosting, Residential ISP, Proxy, VPN, Tor/Botnet, Spam, and Crawlers.
- **Zero External Dependencies**: Pure Python implementation using only the standard library.

---

## Benchmarks & Datasets

Tested on raw IP2Location LITE DB5 and IP2Proxy LITE PX10 datasets:

| Database Mode | Source CSV | Binary (`.bin`) | Compressed (`.bin.gz`) | Ratio | Records | Lookup Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Unified Full (DB5 + PX10)** | 775 MB | 214.1 MB | **43.8 MB** | **17.7x** | 7,946,419 | **< 1.0 µs** |
| **Geo-Only (DB5)** | 293 MB | 57.7 MB | **18.8 MB** | **15.6x** | 2,999,603 | **< 0.8 µs** |
| **Proxy-Only (PX10)** | 482 MB | 48.7 MB | **11.6 MB** | **41.5x** | 2,429,915 | **< 0.8 µs** |

---

## Installation

```sh
pip install .
```

Or run directly without installation:

```sh
python -m grlg.cli --help
```

---

## CLI Usage

### 1. Compile Datasets

Compile raw CSVs into a binary database and compressed `.bin.gz` distribution:

```sh
# Unified Full (Geo + Proxy/Threats)
grlg compile --mode full \
  --db5 IP2LOCATION-LITE-DB5.CSV \
  --px10 IP2PROXY-LITE-PX10.CSV \
  -o goldsrc_geo_full.bin

# Proxy-Only
grlg compile --mode proxy --px10 IP2PROXY-LITE-PX10.CSV -o goldsrc_proxy.bin

# Geo-Only
grlg compile --mode geo --db5 IP2LOCATION-LITE-DB5.CSV -o goldsrc_geo.bin
```

### 2. Lookup an IP Address

```sh
grlg lookup goldsrc_geo_full.bin 8.8.8.8
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
grlg info goldsrc_geo_full.bin
```

### 4. Benchmark Throughput

```sh
grlg benchmark goldsrc_geo_full.bin -n 100000
```

---

## Python API

```python
from grlg.reader import GrlgReader

with GrlgReader("goldsrc_geo_full.bin") as reader:
    record = reader.lookup("1.1.1.1")
    if record:
        print(f"Country: {record.country}, City: {record.city}")
        print(f"Is Datacenter: {record.flags.is_datacenter}")
        print(f"Is Proxy/VPN:   {record.flags.is_proxy}")
        print(f"Is Botnet:      {record.flags.is_botnet}")
```

---

## Binary Format Specification

All multi-byte integers are stored in **Little-Endian** format (`<`).

### Full Unified Layout (Version 3)

- **Header (60 bytes)**:
  - `magic` (4B): `b'GRLG'`
  - `version` (2B): `0x0003`
  - `total_records` (4B): `uint32`
  - `record_size` (2B): `28`
  - `city_count` (4B), `c_idx_off` (4B), `c_data_off` (4B), `c_data_len` (4B)
  - `reg_count` (4B), `r_idx_off` (4B), `r_data_off` (4B), `r_data_len` (4B)
  - `isp_count` (4B), `i_idx_off` (4B), `i_data_off` (4B), `i_data_len` (4B)

- **Record Structure (28 bytes)**:
  - `ip_from` (4B, `uint32`)
  - `ip_to` (4B, `uint32`)
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

---

## Data Attribution & License

This site or product includes IP2Location LITE data available from [https://lite.ip2location.com](https://lite.ip2location.com).

This project is licensed under the [MIT License](LICENSE).
