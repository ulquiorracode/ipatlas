# IPAtlas

[![CI](https://github.com/ulquiorracode/ipatlas/actions/workflows/ci.yml/badge.svg)](https://github.com/ulquiorracode/ipatlas/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)

**IPAtlas** is an ultra-fast, zero-copy binary GeoIP and Proxy/VPN threat intelligence compiler and reader written in Rust.

It fuses disjoint Geolocation (IP2Location) and Threat/Proxy datasets (IP2Proxy) into a unified, flat binary search table designed for edge proxies, high-performance firewalls, gamedev servers, and sub-microsecond packet filters.

---

## Architectural Evolution: From PoC to Systems Engine

IPAtlas originally began as a Python prototype (*archived in `poc/python/`*), which validated the core data models: 1D sweep interval alignment, profile normalization (V4), and cascade coalescing.

In version `0.4.0`, IPAtlas was completely rewritten from the ground up in **Rust** as a production systems-level tool and library:

| Characteristic | Python Prototype (PoC) | Rust Systems Engine (v0.4.0) | Improvement |
| :--- | :--- | :--- | :--- |
| **Hot L1 Lookup Latency** | 6.07 – 8.33 µs | **66.6 ns** (`0.066 µs`) | **~100x faster** |
| **Realistic Random Latency (DRAM/L3)** | 7.50 – 9.20 µs | **120 – 180 ns** | **~50x faster** |
| **Peak Throughput (1 Thread)** | ~120,000 – 164,000 QPS | **~15,000,000 QPS** | **~100x higher** |
| **Compiler Working Memory** | Several GBs (Python object heap) | **Bounded by output table** (~115 MB for 8M rows) | **Zero risk of OOM** |
| **Memory Access** | `struct.unpack` copies | **True Zero-Copy** (`zerocopy` + `mmap`, 100% safe) | **Zero heap allocations** |
| **String Resolution** | Iterative tuple decoding | **SIMD `memchr` slice scan** | **Instant slice views** |
| **File I/O Safety** | In-place overwrite (crash-vulnerable) | **Atomic write-then-rename + sync** | **Crash-safe persistence** |
| **Compression** | External shell subprocess | **Native in-process `zstd` (level 19) + gzip** | **Deterministic & portable** |

---

## Key Highlights

- **Sub-100ns Lookups**: Benchmarked at **66.6 ns** hot cache and **~140 ns** cold/random DRAM access on standard modern CPUs.
- **100% Sound Safe Zero-Copy Kernel Mmap**: Slices verified and referenced directly from kernel page cache via `zerocopy` and `memmap2` without self-referential `unsafe` pointers.
- **Three-Dimensional Architecture**:
  - **Presets & Feature Masks**: Strip unneeded metadata to collapse intervals on the fly.
  - **Optimization Levels (`-O`)**: Semantic rules for cascade interval coalescing, string normalization, and symmetric coordinate quantization.
  - **Generation V4 Layout Tiers**:
    - **V4-Standard (12B)**: `RangeV4` (`from: u32, to: u32, prof_id: u32`), universal 32-bit profile indexing.
    - **V4-Compact (8B)**: `RangeV4Compact` (`from: u32, count: u16, prof_id: u16`), 8 records per 64B cache line (-33% size).
- **Streaming 1D-Sweep Compiler**: Single $O(N + M)$ streaming sweep merging IP2Location and IP2Proxy without loading whole input CSVs into RAM.
- **Zero-Data-Loss Guarantee**: Preserves disjoint threat ranges occurring outside IP2Location Geo coverage.
- **Universal Dataset Support**: Dynamic column detection for all IP2Location (`DB1`, `DB3`, `DB5`, `DB11`) and IP2Proxy (`PX1` – `PX12`) formats.
- **Bitflag Threat Classification**: Single-cycle bitwise checks for Datacenter/Hosting, Residential ISP, Proxy, VPN, Tor/Botnet, Spam, and Crawlers.
- **Zero External Runtime Dependencies**: Reader library compiles in under 1 second with `--no-default-features`.

---

## Generation V4 Layouts: Standard vs Compact

Within Generation V4, IPAtlas offers two layout tiers balancing footprint and capability:

| Layout Tier | Record Size | Fields | Best Used For | 5.3M Production Table Size |
| :--- | :--- | :--- | :--- | :--- |
| **`V4-Standard`** *(Default)* | **12 bytes** | `ip_from: u32`, `ip_to: u32`, `profile_id: u32` | General purpose, unlimited profiles ($> 65k$), global datasets | **61.1 MB** (raw) / 15.4 MB (ZST) |
| **`V4-Compact`** (`--layout compact`) | **8 bytes** | `ip_from: u32`, `count: u16`, `profile_id: u16` | Edge proxies, L1/L2 cache locality (8 recs/64B line), $\le 65k$ profiles | **41.3 MB** (raw, **-32.4%**) / 11.5 MB (ZST) |

> **Automated Protection**: If the number of unique normalized profiles exceeds `65,535` (`u16::MAX`), the compiler automatically falls back from `V4-Compact` to `V4-Standard` without data truncation.

---

## Compiler Optimization Flags (`-O`)

IPAtlas provides a compiler optimization pipeline analogous to C/Rust compilers:

- **`-O0`**: Raw pass-through. No interval coalescing. Preserves raw source intervals.
- **`-O1` (Default)**: Safe lossless cascade coalescing + profile deduplication + empty string pruning. Adjacent intervals with identical attributes are fused: $[A, B] \cup [B+1, C] \to [A, C]$.
- **`-O2`**: `-O1` + whitespace trimming and string normalization.
- **`-O3`**: `-O2` + symmetric coordinate quantization (~10km resolution, unbiased around zero), maximizing interval coalescing ratio for resource-constrained edge routers.

Fine-grained semantic flags are also supported:
```sh
ipatlas compile -O coalesce,lossy-coords,normalize-strings,compact-ranges ...
```

---

## Installation & CLI Usage

### Build from Source

```sh
git clone https://github.com/ulquiorracode/ipatlas.git
cd ipatlas
cargo build --release
```

The optimized binary will be located at `./target/release/ipatlas`.

### 1. Compile Datasets

Compile raw IPv4 / IPv6 CSV datasets into high-performance zero-copy binary databases:

```sh
# Dual-Stack Full Database (Generation V5, IPv4 + IPv6)
ipatlas compile --mode full \
  --geo IP2LOCATION-LITE-DB5.CSV \
  --proxy IP2PROXY-LITE-PX10.CSV \
  --geo-v6 IP2LOCATION-LITE-DB5.IPV6.CSV \
  --proxy-v6 IP2PROXY-LITE-PX10.IPV6.CSV \
  -o ipatlas_full.bin

# Fast Preset Compilation (Cascade Coalescing):
# - firewall: Country + ASN + Threat flags (~7.9 MB binary)
ipatlas compile --preset firewall --geo DB5.CSV --proxy PX10.CSV -o ipatlas_firewall.bin

# - country: Pure Geo-Blocking Country-Only (~5.6 MB binary, 233x reduction!)
ipatlas compile --preset country --geo DB5.CSV -o ipatlas_country.bin

# - city: Country + Region + City + Coordinates without threats (~38 MB binary)
ipatlas compile --preset city --geo DB5.CSV -o ipatlas_city.bin

# V5 Compact Layout (8B V4 records / 36B V6 records, maximum L1/L2 cache locality):
ipatlas compile --preset firewall --layout compact --geo DB5.CSV --proxy PX10.CSV -o firewall_compact.bin

# Distribution Compression (Unix-way):
# Use native system utilities (zstd / pigz) to compress compiled binaries for distribution:
zstd -19 --keep ipatlas_full.bin      # produces ipatlas_full.bin.zst
pigz -k -9 ipatlas_full.bin           # produces ipatlas_full.bin.gz
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

---

## Rust Library API

Add `ipatlas` to your `Cargo.toml`:

```toml
[dependencies]
ipatlas = "0.4.1"
```

For minimal embeddable reader setups without compiler dependencies:

```toml
[dependencies]
ipatlas = { version = "0.4.1", default-features = false }
```

### Example Usage

```rust
use ipatlas::IpAtlasReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = IpAtlasReader::open("ipatlas_full.bin")?;

    // Zero-allocation borrowed lookup (399 ns on 5.3M production database)
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

---

## Known Limitations & Production Notes (v0.4.1)

1. **IPv4 Only**: Generation V4 indexes 32-bit IPv4 address space. Full dual-stack IPv6 index table is scheduled for `v0.5.0`.
2. **Dictionary Capacity**: `ProfileV4` dictionary indices for Region and ISP are 16-bit (`u16::MAX` = 65,535). Designed specifically for LITE and medium-scale datasets. If an index exceeds 65,535, it saturates safely with a warning. An unconstrained 32-byte `ProfileV4Extended` layout for massive Enterprise datasets is planned for `v0.5.0`.
3. **Data Integrity**: Header validation enforces offset boundaries and section non-overlap. Bitrot protection via CRC32/XXH3 checksums within the header is planned for `v0.5.0` (external SHA-256 checksums are currently distributed alongside release archives).

---

## Data Attribution & License

This site or product includes IP2Location LITE data available from [https://lite.ip2location.com](https://lite.ip2location.com).

This project is licensed under the [MIT License](LICENSE).
