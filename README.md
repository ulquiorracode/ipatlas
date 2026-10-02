# IPAtlas

[![CI](https://github.com/ulquiorracode/ipatlas/actions/workflows/ci.yml/badge.svg)](https://github.com/ulquiorracode/ipatlas/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)

**IPAtlas** is an ultra-fast, zero-copy binary GeoIP and Proxy/VPN threat intelligence compiler and reader written in Rust.

It fuses disjoint Geolocation (IP2Location) and Threat/Proxy datasets (IP2Proxy) into a unified, flat binary search table designed for edge proxies, high-performance firewalls, gamedev servers, and sub-microsecond packet filters.

## Architectural Evolution: From PoC to Systems Engine

IPAtlas originally began as a Python prototype (*archived in `poc/python/`*), which validated the core data models: 1D sweep interval alignment, profile normalization (V4), and cascade coalescing.

In version `0.4.0`, IPAtlas was completely rewritten from the ground up in **Rust** as a production systems-level tool and library:

| Characteristic | Python Prototype (PoC) | Rust Systems Engine (v0.4.0) | Improvement |
| :--- | :--- | :--- | :--- |
| **Lookup Latency** | 6.07 – 8.33 µs | **66.6 ns** (`0.066 µs`) | **~100x faster** |
| **Lookup Throughput** | ~120,000 – 164,000 QPS | **~15,000,000 QPS** (single-threaded) | **~90x – 125x higher** |
| **Compiler Memory** | Several GBs (Python lists) | **O(1) Streaming** | **No OOM on 8M records** |
| **Memory Access** | `struct.unpack` copies | **True Zero-Copy** (`zerocopy` + `mmap`) | **Zero allocations** |
| **String Resolution** | Iterative tuple decoding | **SIMD `memchr` slice scan** | **Instant slice views** |
| **Compression** | External shell subprocess | **Native in-process `zstd` (level 19) + gzip** | **Deterministic & portable** |

## Key Highlights

- **Sub-100ns Lookups**: Benchmarked at **66.6 ns** per query (~15M QPS) on standard modern CPUs.
- **True Zero-Copy Kernel Mmap**: Slices mapped directly into kernel page cache via `memmap2` and verified by `zerocopy`.
- **Three-Dimensional Architecture**:
  - **Presets & Feature Masks**: Strip unneeded metadata to collapse intervals on the fly.
  - **Optimization Levels (`-O`)**: Semantic rules for cascade interval coalescing, string normalization, and lossy coordinate quantization.
  - **Memory Layout (V4)**: 12-byte ranges (`from`, `to`, `profile_id`) and 20-byte profile records.
- **Streaming 1D-Sweep Compiler**: Single $O(N + M)$ streaming sweep merging IP2Location and IP2Proxy without loading whole tables into RAM.
- **Universal Dataset Support**: Dynamic column detection for all IP2Location (`DB1`, `DB3`, `DB5`, `DB11`) and IP2Proxy (`PX1` – `PX12`) formats.
- **Bitflag Threat Classification**: Single-cycle bitwise checks for Datacenter/Hosting, Residential ISP, Proxy, VPN, Tor/Botnet, Spam, and Crawlers.
- **Zero External Runtime Dependencies**: Reader library compiles in under 1 second with `--no-default-features`.

## Benchmarks & Datasets

### Lookup Latency & Throughput (Criterion)

Measured on synthetic datasets and IP2Location LITE DB5 + IP2Proxy LITE PX10 (7.95 million intervals):

| Lookup Method | Average Latency | Throughput | Allocation Overhead |
| :--- | :--- | :--- | :--- |
| **`reader.lookup_u32(ip)`** (zero-copy ref) | **66.6 ns** | **15,000,000 QPS** | **0 bytes** (zero allocations) |
| **`reader.lookup_ref(ip)`** (zero-copy ref) | **67.0 ns** | **14,925,000 QPS** | **0 bytes** (zero allocations) |
| **`reader.lookup(ip)`** (owned strings) | **190.5 ns** | **5,250,000 QPS** | Standard `String` allocations |

### Preset Matrix (Cascade Coalescing)

When compiling targeted databases, unused metadata fields are masked and contiguous intervals automatically fuse together:

| Preset | Active Fields | Primary Use Case | Binary (`.bin`) | Zstandard (`.zst`) | Ratio (vs CSV) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`country`** | `Country` | High-speed edge Geo-blocking | **5.6 MB** | **1.2 MB** | **233x** |
| **`threats`** | `ASN, Threats` | Server/API threat & proxy filtering | **6.8 MB** | **2.1 MB** | **120x** |
| **`firewall`** | `Country, ASN, Threats` | Firewall rules & access policies | **7.9 MB** | **2.5 MB** | **100x** |
| **`city`** | `Country, Region, City, Coords` | Classical geolocation without threats | **38.0 MB** | **11.0 MB** | **20x** |
| **`full`** | *All fields included* | Complete unified analytics & security | **95.9 MB** | **27.6 MB** | **26.8x** |

### IPAtlas vs MaxMind GeoLite2 (`.mmdb`)

| Feature / Metric | MaxMind GeoLite2 (`.mmdb`) | IPAtlas (`.bin`) |
| :--- | :--- | :--- |
| **Data Scope** | Geo-Only (separate file for ASN) | **Unified**: Geo + ASN + VPN/Proxy/Threats in 1 file |
| **Lookup Algorithm** | Radix Tree (128-bit bitwise descent) | **Flat Binary Search** $O(\log N)$ ($\le 23$ iterations) |
| **Memory Access Pattern** | Non-contiguous pointer jumps across tree nodes | **Sequential slice access**, CPU L1/L2 cache friendly |
| **Zero-Copy Readiness** | Requires complex tree decoding per node | **Instant struct slice** directly from kernel page cache |
| **Edge Footprint** | ~75 MB (City) / ~6 MB (Country) | **5.6 MB** (`country`) / **7.9 MB** (`firewall`) |
| **Distribution Size** | ~35 MB (City tar.gz) | **1.2 MB** (`country.zst`) / **27.6 MB** (`full.zst`) |

## Compiler Optimization Flags (`-O`)

IPAtlas provides a compiler optimization pipeline analogous to C/Rust compilers:

- **`-O0`**: Raw pass-through. No interval coalescing. Preserves raw source intervals.
- **`-O1` (Default)**: Safe lossless cascade coalescing + profile deduplication + empty string pruning. Adjacent intervals with identical attributes are fused: $[A, B] \cup [B+1, C] \to [A, C]$.
- **`-O2`**: `-O1` + whitespace trimming and string normalization.
- **`-O3`**: `-O2` + lossy coordinate quantization (~10km resolution), maximizing interval coalescing ratio for resource-constrained edge routers.

Fine-grained semantic flags are also supported:
```sh
ipatlas compile -O coalesce,lossy-coords,normalize-strings ...
```

## Installation & CLI Usage

### Build from Source

```sh
git clone https://github.com/ulquiorracode/ipatlas.git
cd ipatlas
cargo build --release
```

The optimized binary will be located at `./target/release/ipatlas`.

### 1. Compile Datasets

Compile raw CSVs into a binary database with automated `.bin.gz` and `.bin.zst` distributions:

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

# Custom Optimization Level:
ipatlas compile --preset firewall -O3 --geo DB5.CSV --proxy PX10.CSV -o firewall_opt.bin
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
Flags:       0x0809 (Proxy/Anonymizer | Datacenter | Commercial)
  Datacenter:  true
  Proxy / VPN: true
  Botnet:      false
  Spam:        false
  Mobile:      false
  Residential: false
Lookup Time: 0.07 µs (67 ns)
```

### 3. Inspect Database Metadata

```sh
ipatlas info ipatlas_full.bin
```

### 4. Benchmark Throughput

```sh
ipatlas bench ipatlas_full.bin -n 1000000
```

## Rust Library API

Add `ipatlas` to your `Cargo.toml`:

```toml
[dependencies]
ipatlas = "0.4.0"
```

For minimal embeddable reader setups without compiler dependencies:

```toml
[dependencies]
ipatlas = { version = "0.4.0", default-features = false }
```

### Example Usage

```rust
use ipatlas::IpAtlasReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = IpAtlasReader::open("ipatlas_full.bin")?;

    // Zero-allocation borrowed lookup (66 ns)
    if let Some(record) = reader.lookup_ref("1.1.1.1".parse()?) {
        println!("Country: {}", record.country);
        println!("City:    {}", record.city);
        println!("Is Datacenter: {}", record.flags.is_datacenter());
        println!("Is Proxy/VPN:   {}", record.flags.is_proxy());
        println!("Is Botnet:      {}", record.flags.is_botnet());
    }

    Ok(())
}
```

## Binary Format Specification (Format V4)

All multi-byte integers are stored in **Little-Endian** format (`<`).

### Full Unified Layout

- **Header (68 bytes)**:
  - `magic` (4B): `b'ATLS'`
  - `version` (2B): `0x0004`
  - `total_records` (4B): `uint32`
  - `record_size` (2B): `12`
  - `profile_count` (4B): `uint32`
  - `profile_offset` (4B): `uint32`
  - `city_count` (4B), `c_idx_off` (4B), `c_data_off` (4B), `c_data_len` (4B)
  - `reg_count` (4B), `r_idx_off` (4B), `r_data_off` (4B), `r_data_len` (4B)
  - `isp_count` (4B), `i_idx_off` (4B), `i_data_off` (4B), `i_data_len` (4B)

- **Range Record Structure (`RangeV4`, 12 bytes)**:
  - `ip_from` (4B, `uint32`)
  - `ip_to` (4B, `uint32`)
  - `profile_id` (4B, `uint32`)

- **Profile Record Structure (`ProfileV4`, 20 bytes)**:
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
