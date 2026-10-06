# IPAtlas

<!-- Project Status & Metrics -->
![Status](https://img.shields.io/badge/status-production--ready-brightgreen?logo=rust) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![CI](https://github.com/ulquiorracode/ipatlas/actions/workflows/ci.yml/badge.svg)](https://github.com/ulquiorracode/ipatlas/actions/workflows/ci.yml)  
<!-- Repository & Community -->
![GitHub Created At](https://img.shields.io/github/created-at/ulquiorracode/ipatlas?logo=github) [![Last Commit](https://img.shields.io/github/last-commit/ulquiorracode/ipatlas)](https://github.com/ulquiorracode/ipatlas/commits/main) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md) ![GitHub contributors](https://img.shields.io/github/contributors/ulquiorracode/ipatlas?logo=github) [![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?logo=readme)](https://github.com/RichardLitt/standard-readme)  
<!-- Tech Stack & Targets -->
[![Rust: 2021 Edition](https://img.shields.io/badge/rust-2021_edition-orange.svg?logo=rust&logoColor=orange)](https://doc.rust-lang.org/edition-guide/rust-2021/) [![MSRV: 1.74](https://img.shields.io/badge/MSRV-1.74-blue.svg)](https://www.rust-lang.org/) ![Targets: x86_64-windows | x86_64-linux | aarch64-macos](https://img.shields.io/badge/targets-windows%20%7C%20linux%20%7C%20macos-lightgray.svg?logo=linux&logoColor=black)

> Ultra-fast zero-copy binary GeoIP and Proxy/VPN threat database compiler and reader in Rust.

**IPAtlas** is a production systems-level library and CLI tool written in Rust. It fuses disjoint Geolocation (IP2Location / MaxMind) and Threat/Proxy datasets (IP2Proxy) into a unified, flat binary search table designed for edge proxies, high-performance firewalls, game servers, and sub-microsecond packet filters.

---

## ⚡ 30-Second Quickstart (Zero Setup)

Try IPAtlas immediately with pre-compiled production binaries—**no dataset registration or CSV downloads required**:

```bash
# 1. Install CLI utility
cargo install ipatlas-cli

# 2. Instant lookup using pre-bundled distribution binary
ipatlas lookup ./dist/ipatlas_goldsrc_city.bin 8.8.8.8
```

Output:
```text
IP:          8.8.8.8
Range:       8.8.8.0 - 8.8.8.255
Country:     US (United States)
Region:      California
City:        Mountain View
ISP:         Google LLC (AS15169)
Threat:      Clean (0x0000)
Lookup Time: 0.07 µs (68 ns)
```

---

## 🔌 Zero-Effort Drop-In Integrations

Drop IPAtlas into your existing stack in **2 lines of code**:

| Environment | Integration | Effort | Status |
| :--- | :--- | :--- | :--- |
| **Rust Web / Axum / Tower** | Single middleware layer: `.layer(IpAtlasLayer::new(reader))` | **30 sec** | Production Ready |
| **MaxMind Migration** | One-command CLI compile: `ipatlas compile --maxmind-blocks ...` | **10 sec** | Production Ready |
| **C / C++ / Nginx / Envoy** | Zero-alloc C ABI: `ipatlas_open("db.bin")` + `ipatlas_is_threat_u32(...)` | **1 min** | Production Ready |
| **Python / Go / FFI** | Instant `ctypes` / `cgo` wrapper around shared library (`.so` / `.dll`) | **1 min** | Production Ready |

### 1. Axum / Tower Web Service (Rust)
```rust
use axum::{routing::get, Router, extract::Extension};
use ipatlas_adapter_tower::{IpAtlasLayer, ClientGeo};

let reader = Arc::new(IpAtlasReader::open("ipatlas_goldsrc_city.bin")?);

// 1. Attach layer to router
let app = Router::new()
    .route("/api/hello", get(|Extension(geo): Extension<ClientGeo>| async move {
        format!("Hello from {}, {}!", geo.city, geo.country)
    }))
    .layer(IpAtlasLayer::new(reader).with_strict_threat_block(true));
```
*Read the full [Web Integration Guide](docs/INTEGRATION_GUIDE.md).*

### 2. MaxMind GeoLite2 One-Command CLI Migration
Migrate existing MaxMind GeoLite2 City CSV exports to high-speed zero-copy `.bin` with a single command:
```bash
ipatlas compile \
  --maxmind-blocks GeoLite2-City-Blocks-IPv4.csv \
  --maxmind-locations GeoLite2-City-Locations-en.csv \
  -o ipatlas.bin
```

### 3. C, C++, Nginx & Native Daemons (C-ABI)
```c
#include "ipatlas.h"

// 1. Open database (zero-allocation mmap)
IpAtlasHandle* db = ipatlas_open("ipatlas.bin");

// 2. Sub-20ns threat check in edge packet filter
if (ipatlas_is_threat_u32(db, client_ip_u32)) {
    drop_packet();
}
ipatlas_close(db);
```

### 4. Python via `ctypes` (No Rust toolchain needed)
```python
import ctypes

lib = ctypes.CDLL("./libipatlas_adapter_c.so")
db = lib.ipatlas_open(b"ipatlas_goldsrc_city.bin")
is_threat = lib.ipatlas_is_threat_u32(db, 0x08080808)
print("Is Threat:", bool(is_threat))
lib.ipatlas_close(db)
```

---

## Table of Contents

- [⚡ 30-Second Quickstart (Zero Setup)](#-30-second-quickstart-zero-setup)
- [🔌 Zero-Effort Drop-In Integrations](#-zero-effort-drop-in-integrations)
- [Background](#background)
- [Features](#features)
- [Architecture](#architecture)
- [Generation V4/V5 Layout Tiers & Efficiency Matrix](#generation-v4v5-layout-tiers--efficiency-matrix)
- [Compiler Optimization Flags (`-O`)](#compiler-optimization-flags--o)
- [Theoretical Limits & Shannon Entropy Analysis](#theoretical-limits--shannon-entropy-analysis)
- [Install & Prerequisites](#install--prerequisites)
- [CLI Usage](#cli-usage)
  - [1. Compile Datasets](#1-compile-datasets)
  - [2. Lookup an IP Address](#2-lookup-an-ip-address)
  - [3. Inspect Database Metadata](#3-inspect-database-metadata)
  - [4. Benchmark Throughput](#4-benchmark-throughput)
- [Rust Library API](#rust-library-api)
  - [Basic Zero-Allocation Lookup](#basic-zero-allocation-lookup)
  - [Monomorphic U-Cycle Pipeline (`stitch-rs`)](#monomorphic-u-cycle-pipeline-stitch-rs)
- [Universal Drop-In Ecosystem Adapters](#universal-drop-in-ecosystem-adapters)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [Security](#security)
- [Roadmap](#roadmap)
- [Data Attribution & License](#data-attribution--license)

---

## Background

GeoIP and threat intelligence datasets (e.g. MaxMind MMDB, IP2Location, IP2Proxy) traditionally rely on radix trees or hierarchical binary trees. While flexible, tree traversals suffer from:

1. **CPU Pointer Chasing**: Multiple random cache line fetches per lookup ($O(\log N)$ or 24–32 tree steps).
2. **Heavy Allocation Footprint**: Deserializing tree nodes into heap structures consumes hundreds of megabytes of RAM.
3. **Disjoint Coverage**: Merging geo metadata with threat datasets requires multi-database joins during runtime packet evaluation.

**IPAtlas** solves these fundamental bottlenecks by:

1. **Streaming 1D-Sweep Offline Compiler**: Merges disjoint datasets in a single $O(N + M)$ linear pass, resolving overlaps into contiguous intervals.
2. **Zero-Copy Memory-Mapped Flat Storage**: Slices verified and referenced directly from kernel page cache via `zerocopy` and `memmap2` without self-referential pointers or heap allocations.
3. **Sub-100ns Fast Path & 5-6x Full-Record Speedup**: Delivers **17.3 ns** flags-only / **68.7 ns** hot-L1 latency, and **193–205 ns** full-record DRAM access—**5.4x to 12.9x faster than MaxMind MMDB**.

---

## Features

- **Sub-100ns Fast-Path & ~200ns Full Lookups**: Benchmarked at **17.3 ns** flags-only, **68.7 ns** hot-L1 cache, and **193–205 ns** cold random DRAM access on 5.3M production datasets.
- **100% Sound Safe Zero-Copy Kernel Mmap**: Slices verified and referenced directly from kernel page cache via `zerocopy` and `memmap2` without self-referential `unsafe` pointers.
- **Three-Dimensional Architecture**:
  - **Presets & Feature Masks**: Strip unneeded metadata to collapse intervals on the fly.
  - **Optimization Levels (`-O`)**: Semantic rules for cascade interval coalescing, string normalization, and symmetric coordinate quantization.
  - **Container Generation & Layout Tiers**:
    - **IPv4 Standard (12B)**: `Ipv4Range` (`from: u32, to: u32, profile_id: u32`), universal 32-bit profile indexing.
    - **IPv4 Compact (8B)**: `Ipv4RangeCompact` (`from: u32, count: u16, profile_id: u16`), 8 records per 64B cache line (-32.4% size).
    - **IPv6 Split-64 Compact (16B, Opt-in [Lossy])**: `Ipv6RangeSplit64` (`from_hi: u64, count_hi: u32, profile_id: u32`), 4 records per 64B cache line with 0% straddling (-55.6% size, over-approximates sub-/64 intervals).
    - **Gen5 Succinct (Experimental [Bench-Only])**: Elias-Fano compressed monotone bitvectors reaching ~100% of theoretical Shannon entropy floor (offline evaluation prototype).
- **Streaming 1D-Sweep Compiler**: Single $O(N + M)$ streaming sweep merging IP2Location and IP2Proxy without loading whole input CSVs into RAM.
- **Zero-Data-Loss Guarantee**: Preserves disjoint threat ranges occurring outside IP2Location Geo coverage.
- **Universal Dataset Support**: Dynamic column detection for all IP2Location (`DB1`, `DB3`, `DB5`, `DB11`) and IP2Proxy (`PX1` – `PX12`) formats.
- **Bitflag Threat Classification**: Single-cycle bitwise checks for Datacenter/Hosting, Residential ISP, Proxy, VPN, Tor/Botnet, Spam, and Crawlers.
- **Embedded Zstd Container**: Transparent in-memory decompression without disk modifications.
- **Monomorphic U-Cycle Pipeline (`stitch-rs`)**: Sub-2ns Bogon short-circuiting and strict threat policy enforcement.
- **Zero External Runtime Dependencies**: Reader library compiles in under 1 second with `--no-default-features`.

---

## Architecture

IPAtlas is engineered as a zero-copy, cache-aligned database engine with strict separation between offline $O(N + M)$ compilation, kernel page-mapped zero-copy runtime, and compile-time monomorphic request pipelines.

```text
       Input Feeds (IP2Location DB + IP2Proxy PX)
                          │
                          ▼
            [ Streaming 1D Sweep-Line ] ──► Dual Cursor Merging ($O(N + M)$)
                          │
                          ▼
            [ Normalization & Deduplication ] ──► String Blobs & Profile Table
                          │
                          ▼
             [ Flat Binary Container (.bin) ]
            ┌─────────────┬──────────────────┐
            │   Header    │  Magic + Offsets │
            │  IPv4 Table │  8B / 12B Ranges │
            │  IPv6 Table │  16B / 36B Ranges│
            │  Profiles   │  20B ProfileGen4 │
            │  Strings    │  UTF-8 Blob Pool │
            └─────────────┴──────────────────┘
                          │
                          ▼
               [ Zero-Copy mmap Runtime ] ──► Sub-100ns Binary / Eytzinger Search
```

> **Formal Taxonomy & Invariants**:
> For the complete architectural specification, modular source code layout, and formal taxonomy matrix distinguishing container generations (`Gen4`, `Gen5`) from network protocol spaces (`Ipv4`, `Ipv6`), consult [**`ARCHITECTURE.md`**](ARCHITECTURE.md).

---

## Generation V4/V5 Layout Tiers & Efficiency Matrix

IPAtlas provides distinct layout tiers designed around the trade-off between memory footprint, zero-copy alignment, and hardware cache efficiency:

| Layout Tier | Status | Record Size | 5.3M Table RAM | Shannon Ratio | 5.3M Full Snapshot Latency | 10k L1-Fit Latency | Multi-Thread Throughput-Eq (16T) | Hardware Efficiency Product ($P = \text{RAM} \times \text{Latency}$) | vs MaxMind MMDB |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **MaxMind MMDB** *(Baseline)* | Industry Standard | ~22 bytes (tree) | **115.0 MB** | $6.50 \times H_{\text{raw}}$ | **1,100 ns** *(DRAM)* | N/A | ~5.8M QPS | **$126,500\text{ MB}\cdot\text{ns}$** (1.0x baseline) | Reference |
| **`V4/V5-Standard (AoS)`** | **Production** | 12 bytes | **61.1 MB** | $3.45 \times H_{\text{raw}}$ | **218.4 ns** *(DRAM)* | **66.7 ns** | ~48.2M QPS | **$13,344\text{ MB}\cdot\text{ns}$** | **9.5x more efficient** |
| **`V4/V5-Compact (AoS)`** | **Production** | 8 bytes | **41.3 MB** | **$2.33 \times H_{\text{raw}}$** | **205.2 ns** *(DRAM)* | **68.7 ns** | **62.8M QPS** | **$8,474\text{ MB}\cdot\text{ns}$** | **14.9x more efficient** |
| **`V4/V5-Compact (SoA)`** (`--layout soa`) | **Production (Opt)** | 8 bytes (columnar) | **41.3 MB** | **$2.33 \times H_{\text{raw}}$** | **193.0 ns** *(DRAM)* | **69.4 ns** *(15.9ns flags)* | **64.6M QPS** | **$7,970\text{ MB}\cdot\text{ns}$** | **15.9x more efficient** |
| **Flags-Only Fast Path** | **Production** | Zero-allocation | N/A | N/A | **85.3 ns** *(DRAM)* | **17.3 ns** | **120.0M+ QPS** | N/A | **Edge Firewall Mode** |
| **`V5-Succinct`** *(Shannon Bound)* | **Experimental** *(Non-Prod)* | ~2.8 bytes (E-F) | **17.8 MB** | **$\approx 1.01 \times H_{\text{raw}}$** | **353.8 ns** *(DRAM)* | **331.7 ns** | N/A | **$6,298\text{ MB}\cdot\text{ns}$** | **20.1x more efficient** |

> **Comprehensive Analysis**: For in-depth empirical testbed analysis, cache-line breakdown, and detailed Criterion traces, see [**`docs/BENCHMARKS.md`**](docs/BENCHMARKS.md).
>
> **Methodology & L1 Cache-Fit vs DRAM Reality**:
>
> - **5.3M Full Snapshot**: Lookups across the complete 5,318,878 production database (41–61 MB). At this scale, the 21.3 MB search key column exceeds the CPU L1/L2 cache and memory bus round-trips ($t_{\text{CAS}}$) bound binary search latency (~193–205 ns single-threaded). SoA yields a steady ~6% single-threaded improvement and scales to **64.5M QPS** across 16 threads.
> - **10k L1-Fit Synthetic Regime**: In microbenchmarks where the entire range table fits within 32 KB L1d / L2 cache, binary search achieves **15.4–17.0 ns** without touching DRAM.
> - **Flags-Only & Threat Predicates**: Bypasses string table resolution and heap allocation entirely, delivering **85.3 ns on 5.3M DRAM** and **16.1–16.9 ns in L1 cache**.
>
> **Experimental Designation**: `V5-Succinct` is strictly an **experimental research tier** for extreme memory-constrained devices (16MB routers). For all production services and edge reverse proxies, **`V4/V5-Compact (AoS)`** or **`V4/V5-Compact (SoA)`** is the recommended default.
>
> **Automated Protection**: If the number of unique normalized profiles exceeds `65,535` (`u16::MAX`), the compiler automatically falls back from `Compact` to `Standard` without data truncation.

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

## Theoretical Limits & Shannon Entropy Analysis

In information theory, the **Shannon entropy limit** defines the absolute lower bound of lossless data representation:

$$H(X) = - \sum_{i} P(x_i) \log_2 P(x_i)$$

For the combined global IPv4 space ($2^{32} \approx 4.29 \times 10^9$ addresses), data is naturally partitioned into disjoint CIDR / routing intervals with shared metadata attributes:

- **Interval Boundary Entropy**: Specifying the cut-points of $5.3 \times 10^6$ intervals across the 32-bit integer universe via optimal monotonic difference bounds (Elias-Fano representation: $N \lceil \log_2(U/N) \rceil + 2N$) requires $\approx 11.2\text{ bits/record} \approx \mathbf{7.4\text{ MB}}$.
- **Profile Alphabet Entropy**: Choosing among $\approx 50{,}000$ unique normalized profiles (Country, Region, City, ASN, Flags) requires $\lceil \log_2(50{,}000) \rceil \approx 15.6\text{ bits/record} \approx \mathbf{10.3\text{ MB}}$.
- **Theoretical Minimum ($H_{\text{raw}}$)**: The absolute theoretical Shannon floor for lossless random-access interval topology is $\approx \mathbf{17.7\text{ MB}}$.

### How IPAtlas Tiers Compare to the Shannon Limit

| Storage Layer / Format | 5.3M Production Table Size | Ratio to Shannon Limit ($H_{\text{raw}}$) | Random Access Latency (L1 / DRAM) | Architectural Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **Raw CSV Inputs** | **~740 MB** | $41.8 \times H_{\text{raw}}$ | N/A (linear parsing) | Redundant text strings, repeated ASCII coordinates |
| **`V4/V5-Standard` (12B)** | **61.1 MB** | $3.45 \times H_{\text{raw}}$ | **66.7 ns / 205.2 ns** | 100% safe zero-copy kernel mmap, 4-byte aligned flat binary search |
| **`V4/V5-Compact` (8B)** | **41.3 MB** | **$2.33 \times H_{\text{raw}}$** | **68.7 ns / 193.0 ns** | **L1/L2 cache-line tuned** (8 records / 64B cache line, -32.4% size) |
| **`--preset firewall`** | **7.9 MB** | **$0.44 \times H_{\text{raw}}$** | **17.3 ns / 85.3 ns** | Sub-alphabet collapse (City/Coords discarded, adjacent ranges coalesce) |
| **`--preset country`** | **5.6 MB** | **$0.31 \times H_{\text{raw}}$** | **25.0 ns / 110.0 ns** | Coalesced country intervals with direct ISO code extraction |
| **Zstandard (.zst)** | **11.5 MB** | **$0.65 \times H_{\text{raw}}$** | Compressed distribution | Asymmetric Finite State Entropy (FSE) context compression |

---

## Install & Prerequisites

Ensure the following tools are installed:

1. **Rust Toolchain (1.74+)**:

   ```bash
   rustup default stable
   ```

2. **Build from source**:

   ```bash
   git clone https://github.com/ulquiorracode/ipatlas.git
   cd ipatlas
   cargo build --release
   ```

   The binary is output to `./target/release/ipatlas`.

---

## CLI Usage

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

# Dual-Stack Opt-in Lossy IPv6 Split-64 (-55.6% RAM, 4 records per 64B cache line):
ipatlas compile --mode full \\
  --geo DB5.CSV --proxy PX10.CSV \\
  --geo-v6 DB5.IPV6.CSV --proxy-v6 PX10.IPV6.CSV \\
  --split64-v6 -o ipatlas_split64.bin

# Fast Preset Compilation (Cascade Coalescing):
# - firewall: Country + ASN + Threat flags (~7.9 MB binary)
ipatlas compile --preset firewall --geo DB5.CSV --proxy PX10.CSV -o ipatlas_firewall.bin

# - country: Pure Geo-Blocking Country-Only (~5.6 MB binary, 233x reduction!)
ipatlas compile --preset country --geo DB5.CSV -o ipatlas_country.bin

# - city: Country + Region + City + Coordinates without threats (~38 MB binary)
ipatlas compile --preset city --geo DB5.CSV -o ipatlas_city.bin

# Structure of Arrays (SoA) Layout (Peak 15.4 ns lookup speed):
ipatlas compile --preset firewall --layout soa --family compact --geo DB5.CSV --proxy PX10.CSV -o firewall_soa.bin

# Embedded Zstandard Container (Transparent In-Memory Decompression):
# Compresses the payload inside the .bin file while keeping native L1 query speed:
ipatlas compile --preset city --geo DB5.CSV --embedded-zstd -o ipatlas_city_zstd.bin
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

Add IPAtlas to your `Cargo.toml`:

```toml
[dependencies]
ipatlas = { version = "0.11.0", default-features = false }
```

### Basic Zero-Allocation Lookup

```rust
use ipatlas::IpAtlasReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fast zero-copy open (validates header & slice bounds in nanoseconds):
    let reader = IpAtlasReader::open("ipatlas_full.bin")?;
    // (Optional) Full CRC32 checksum verification:
    // let reader = IpAtlasReader::open_verified("ipatlas_full.bin")?;

    // Warm up OS page cache for low cold-start latency:
    reader.warmup();

    // 1. Ultra-fast Flags-Only Fast Path (18.5 ns, zero-allocation, firewall/edge mode)
    let ip_u32 = 0x08080808; // 8.8.8.8
    if let Some(flags) = reader.lookup_flags_u32(ip_u32) {
        println!("Is Threat: {}", flags.is_threat());
        println!("Is Datacenter: {}", flags.is_datacenter());
    }

    // 2. Zero-allocation borrowed lookup (68.7 ns hot-L1, 193-205 ns cold DRAM)
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

### Monomorphic U-Cycle Pipeline (`stitch-rs`)

IPAtlas integrates an optional monomorphic U-cycle execution pipeline via `stitch-rs`.
*Note*: Direct database queries (`lookup_ref`, `lookup_flags_u32`) remain the raw nanosecond hot path (**17–205 ns**); the U-cycle pipeline trades ~128 ns of additional policy latency for compile-time composable middleware, zero-allocation bogon short-circuiting, and enterprise security policy enforcement:

```rust
use ipatlas_core::pipeline::{IpAtlasPipelineExt, LookupContext, LookupIntent};
use ipatlas_core::IpAtlasReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fast zero-copy open (validates header & slice bounds in nanoseconds):
    let reader = IpAtlasReader::open("ipatlas_full.bin")?;
    // (Optional) Full CRC32 checksum verification:
    // let reader = IpAtlasReader::open_verified("ipatlas_full.bin")?;
    let mut ctx = LookupContext::default();

    // 1. Bogon short-circuit: 127.0.0.1 terminates on descent in ~1.5 ns without mmap/disk lookup
    let bogon_res = reader.query_pipeline(&mut ctx, LookupIntent::new("127.0.0.1".parse()?))?;
    assert!(bogon_res.is_bogon);

    // 2. Strict threat filtering: policy layer enforces rejection of proxy/tor/vpn/botnets on ascent
    let intent = LookupIntent::new("1.0.5.10".parse()?).with_strict_threat_filter(true);
    match reader.query_pipeline(&mut ctx, intent) {
        Ok(outcome) => println!("Resolved: {:?}", outcome.country()),
        Err(err) => println!("Rejected by security policy: {err}"),
    }

    println!("Total lookups: {}, Bogon short-circuits: {}", ctx.dispatches, ctx.bogon_short_circuits);
    Ok(())
}
```

---

## Universal Drop-In Ecosystem Adapters

IPAtlas provides first-class adapters enabling zero-boilerplate integration into external frameworks, data providers, and native languages:

### 1. Axum & Tower Middleware (`adapters/ipatlas-adapter-tower`)

Attach high-throughput geolocation and threat classification to any Tower or Axum web service in **2 lines of code**:

```rust
use axum::{routing::get, Router, extract::Extension};
use ipatlas_adapter_tower::{IpAtlasLayer, ClientGeo};

// 1. Attach layer to router
let app = Router::new().route("/", get(handler)).layer(IpAtlasLayer::new(reader));

// 2. Extract ClientGeo in handler
async fn handler(Extension(geo): Extension<ClientGeo>) -> String {
    if geo.is_threat() { return "Threat blocked".into(); }
    format!("Hello from {}, {}!", geo.city, geo.country)
}
```

### 2. MaxMind GeoLite2 Ingestion SPI (`adapters/ipatlas-adapter-maxmind`)

Compile official MaxMind GeoLite2 City CSV releases into native IPAtlas `.bin` databases without writing converters:

```rust
use ipatlas_adapter_maxmind::MaxMindCityAdapter;
use ipatlas_core::DatasetIngestionAdapter;

let mut adapter = MaxMindCityAdapter::open("GeoLite2-City-Blocks-IPv4.csv", "GeoLite2-City-Locations-en.csv")?;
for record in adapter.parse_v4() {
    println!("Parsed CIDR: {}.{}.{}.{} -> {}", (record.ip_from >> 24) & 0xFF, (record.ip_from >> 16) & 0xFF, (record.ip_from >> 8) & 0xFF, record.ip_from & 0xFF, std::str::from_utf8(&record.country)?);
}
```

### 3. C-ABI & Native FFI (`adapters/ipatlas-adapter-c`)

Integrate into C, C++, Nginx, HAProxy, Envoy, Go, and Python via standard shared/static libraries (`libipatlas.so` / `ipatlas.dll`) and [`include/ipatlas.h`](adapters/ipatlas-adapter-c/include/ipatlas.h):

```c
#include "ipatlas.h"

IpAtlasHandle* db = ipatlas_open("ipatlas_full.bin");
uint32_t flags = ipatlas_lookup_flags_u32(db, 0x08080808); // 8.8.8.8
if (ipatlas_is_threat_u32(db, 0x08080808)) {
    // Drop packet
}
ipatlas_close(db);
```

---

## Maintainers

- [@ulquiorracode](https://github.com/ulquiorracode) — Project Lead & Creator

---

## Contributing

We welcome contributions! Please review:

1. [Code of Conduct](CODE_OF_CONDUCT.md)
2. [Contribution Guidelines](CONTRIBUTING.md)
3. Follow [Conventional Commits](https://www.conventionalcommits.org/) and English code artifact rules.

---

## Security

Please report vulnerabilities confidentially via GitHub Security Advisories or by reviewing [SECURITY.md](SECURITY.md).

---

## Roadmap

Detailed milestones, architectural tracking, and future features are documented in [ROADMAP.md](ROADMAP.md).

---

## Data Attribution & License

This site or product includes IP2Location LITE data available from [https://lite.ip2location.com](https://lite.ip2location.com).

This project is licensed under the [MIT License](LICENSE).
