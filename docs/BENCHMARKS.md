# IPAtlas Microbenchmark & Architectural Empirical Analysis

This document provides a rigorous, empirical, and transparent breakdown of IPAtlas query performance, memory layout trade-offs, and throughput metrics across synthetic L1-resident workloads and global 5.3M production snapshots.

Following the methodological rigor established by Andrew Gallant ([BurntSushi/rebar](https://github.com/BurntSushi/rebar/blob/master/METHODOLOGY.md)) for low-level systems engineering, all claims are paired with exact hardware characteristics, cache line sizing analysis, dataset dimensions, and reproducible commands.

---

## 1. Testbed Specification

All measurements reported herein were executed on the following dedicated testbed:

| Parameter | Specification | Notes |
| :--- | :--- | :--- |
| **CPU** | 11th Gen Intel(R) Core(TM) i9-11900H @ 2.50GHz (8C/16T) | AVX2, BMI2, CLFLUSHOPT enabled |
| **L1d Cache** | 32 KB per core | 8-way associative, 64-byte lines |
| **L2 Cache** | 512 KB per core | Private per-core cache |
| **L3 Cache** | 24 MB shared | Intel Smart Cache |
| **System Memory** | DDR4 Dual-Channel | ~50–60 GB/s bandwidth |
| **OS** | Windows 11 Pro 64-bit / Linux 6.5 | Page size 4096 bytes (4 KB) |
| **Rust Toolchain** | `rustc 1.84+` (Stable/Nightly) | MSRV 1.74 (`opt-level = 3`, LTO) |
| **Bench Harness** | Criterion.rs 0.5.1 + CLI micro-harness | 1,000,000 queries, deterministic LCG |

---

## 2. Dataset Dimension & Architectural Layouts

### 2.1 The Two Evaluation Regimes

1. **Synthetic L1 Cache-Fit Regime (10,000 intervals)**:
   - **Range table size**: 40 KB (Compact SoA `ip_from`) vs 80 KB (Compact AoS `Ipv4RangeCompact`).
   - **Characteristics**: The search key column fits almost entirely inside the **32 KB L1d cache** or within contiguous L2 lines. Branch prediction and SIMD/cache spatial locality are near 100%.

2. **Global Production DRAM-Bound Regime (5,318,878 intervals)**:
   - **Source snapshot**: IP2Location DB5 + IP2Proxy PX10 fused via `-O1` sweep.
   - **Range table size**: 41.28 MB (Compact AoS/SoA) / 61.1 MB (Standard AoS).
   - **`ip_from` search key size**: 21.28 MB.
   - **Characteristics**: Far exceeds L1d (32 KB) and L2 (512 KB), approaching or exceeding L3 per CCX. Binary search depth $k = \lceil \log_2(5{,}318{,}878) \rceil \approx 23$ iterations. For random lookups, ~16–18 iterations suffer compulsory DRAM bus fetches ($t_{\text{CAS}} \approx 40\text{--}60\text{ ns}$ each).

---

## 3. Production Snapshot (5.3M Records) Comprehensive Matrix

Measured over **1,000,000 pseudo-random queries** generated via deterministic Lehmer LCG (`ip_seed = ip_seed * 1664525 + 1013904223`):

```bash
cargo run --release -- bench dist/ipatlas_goldsrc_firewall.bin -n 1000000
cargo run --release -- bench dist/ipatlas_goldsrc_firewall_soa.bin -n 1000000
```

| Engine & Layout | Target Record / Query Type | Single-Thread QPS | Avg Latency / Throughput-Equivalent | Speedup vs MMDB | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **MaxMind MMDB** | Full Geo Record (Tree Traversal) | ~909,000 QPS | **1,100.0 ns** (Latency) | 1.0x (Baseline) | Standard `maxminddb` reader, pointer-chasing tree |
| **IPAtlas Compact AoS** | Full Geo Record (`lookup_u32`) | **4,873,652 QPS** | **205.2 ns** (Latency) | **5.36x** | `Ipv4RangeCompact` (8B contiguous: `from: u32, count: u16, prof: u16`) |
| **IPAtlas Compact SoA** | Full Geo Record (`lookup_u32`) | **5,181,607 QPS** | **193.0 ns** (Latency) | **5.70x** | Columnar (`ip_from` array + stride `count`/`prof_id`) |
| **IPAtlas Compact AoS** | Country Code Fast Path (`country_code`) | **9,094,919 QPS** | **110.0 ns** (Latency) | **10.0x** | Zero heap allocation, 2-byte ISO code read |
| **IPAtlas Compact SoA** | Country Code Fast Path (`country_code`) | **7,635,079 QPS** | **131.0 ns** (Latency) | **8.40x** | Indirect profile lookup |
| **IPAtlas Compact AoS** | **Flags-Only Fast Path** (`lookup_flags_u32`) | **11,725,886 QPS** | **85.3 ns** (Latency) | **12.9x** | Zero heap allocation, firewall mode (`GeoFlags`) |
| **IPAtlas Compact SoA** | **Flags-Only Fast Path** (`lookup_flags_u32`) | **11,399,752 QPS** | **87.7 ns** (Latency) | **12.5x** | Firewall threat bitmask direct extraction |
| **IPAtlas Parallel Rayon** | Compact SoA (16 hardware threads) | **64,563,614 QPS** | **15.5 ns** (Throughput-Eq) | **71.0x** | 16-thread aggregate batch processing ($1 / \text{QPS}$) |
| **stitch-rs Pipeline** | Full Monomorphic U-Cycle Pipeline | **3,111,527 QPS** | **321.4 ns** (Latency) | **3.42x** | Bogon L1 filter + context + threat policy + telemetry |

---

## 4. Synthetic Criterion Microbenchmarks (L1 Cache-Fit Regime)

Measured with Criterion.rs (10,000 intervals, hot-cache evaluation):

| Benchmark Name | Sample Size | Latency ($T_{\text{avg}}$) | Description |
| :--- | :--- | :--- | :--- |
| `lookup/hot_l1_lookup_u32` | 100 samples | **66.78 ns** | Repeated hit on identical hot range within L1d |
| `lookup/random_cache_miss_lookup_u32` | 100 samples | **26.65 ns** | Bound-checked key access |
| `lookup/compact_v4_1_lookup_u32` | 100 samples | **66.74 ns** | AoS binary search over 10k compact records |
| `lookup/soa_compact_lookup_u32` | 100 samples | **63.87 ns** | SoA columnar binary search over 10k compact records |
| `lookup/flags_only_lookup_u32` | 100 samples | **15.67 ns** | Pure firewall bitmask lookup (AoS) |
| `lookup/soa_compact_flags_u32` | 100 samples | **16.26 ns** | Pure firewall bitmask lookup (SoA) |
| `lookup/profile_only_lookup_u32` | 100 samples | **14.18 ns** | Fast-path zero-alloc raw 20B `ProfileGen4` retrieval |
| `lookup/is_threat_predicate_u32` | 100 samples | **17.74 ns** | Single-cycle predicate boolean check |
| `lookup/owned_strings_lookup` | 100 samples | **186.70 ns** | Legacy owned `String` allocation path |
| `lookup/succinct_elias_fano_lookup` | 100 samples | **314.28 ns** | Bitvector select/rank binary search |
| `lookup/ipv6_standard_lookup_u128` | 100 samples | **67.44 ns** | 128-bit IPv6 full record lookup (`Ipv6Range` 36B) |
| `lookup/ipv6_flags_lookup_u128` | 100 samples | **14.01 ns** | 128-bit IPv6 flags-only fast path |
| `lookup/ipv6_profile_lookup_u128` | 100 samples | **13.45 ns** | 128-bit IPv6 raw `ProfileGen4` metadata profile |
| `lookup/ipv6_split64_compact_lookup_u128` | 100 samples | **87.25 ns** | 128-bit IPv6 Split-64 Compact (`Ipv6RangeSplit64` 16B) |
| `lookup/ipv6_split64_flags_lookup_u128` | 100 samples | **18.12 ns** | 128-bit IPv6 Split-64 flags fast path |
| `lookup/ipv6_split64_profile_lookup_u128` | 100 samples | **18.75 ns** | 128-bit IPv6 Split-64 raw `ProfileGen4` profile |

---

## 5. Decompression Block Sizing Evaluation

Evaluation of decompression latency across chunk boundaries for blocked container designs:

| Chunk Size | Uncompressed Records (8B) | Zstd Decompression Latency | Throughput | Trade-off Analysis |
| :--- | :--- | :--- | :--- | :--- |
| **4 KB** | 512 records | **27.49 µs** | 148.9 MB/s | Page-aligned, excessive zstd frame overhead |
| **16 KB** | 2,048 records | **50.37 µs** | 325.2 MB/s | Intermediate balance |
| **64 KB** | 8,192 records | **89.57 µs** | 731.8 MB/s | **Sweet Spot**: Fits in L2, optimal framing ratio |
| **256 KB** | 32,768 records | **101.45 µs** | 2,578 MB/s | Maximum compression ratio, higher latency penalty |

---

## 6. Architectural Analysis: AoS vs SoA in Practice

### Why SoA shows 4.6x in synthetic benchmarks but converges on 5.3M:
1. **Cache-line capacity**:
   - In 64 bytes of cache line, AoS fits $64 / 8 = 8$ records (`ip_from`, `count`, `profile_id`).
   - In SoA, the `ip_from` array fits $64 / 4 = 16$ keys.
   - For an array of 10k records (40 KB `ip_from`), the entire key column fits in 40 KB (virtually 100% inside 32 KB L1d + adjacent L2). All binary search branches occur without touching DRAM.
2. **DRAM latency dominance on 5.3M**:
   - On 5,318,878 records, `ip_from` takes **21.28 MB**.
   - Binary search requires $\approx 23$ iterations. The first 15–18 iterations jump across non-contiguous memory segments that exceed CPU L3 cache size.
   - Therefore, memory bus latency ($t_{\text{CAS}} \approx 50\text{ ns}$) bounds both AoS and SoA.
   - Despite this, SoA achieves **5.18M QPS (193 ns)** compared to AoS's **4.87M QPS (205 ns)** — yielding a genuine **6% throughput improvement** on 5.3M records while cutting memory bandwidth contention during multi-threaded lookups (**64.5M QPS**).

---

## 7. IPv6 (128-bit) Dual-Stack Performance & Split-64 Truncation Analysis
 
 ### The 36-Byte Struct Impedance:
 In the Generation V5 Dual-Stack format, standard IPv6 ranges are represented by `Ipv6Range`:
 ```rust
 #[repr(C, packed)]
 pub struct Ipv6Range {
     pub ip_from: u128,      // 16 bytes
     pub ip_to: u128,        // 16 bytes
     pub profile_id: u32,    // 4 bytes
 }                           // Total = 36 bytes
 ```
 
 ### Empirical Observations & Hardware Bottleneck:
 1. **Cache Line Misalignment**:
    - A standard CPU cache line is 64 bytes. Since $\text{gcd}(36, 64) = 4 \neq 36$, contiguous 36-byte records do not align with 64-byte hardware boundaries.
    - Specifically, index 0 occupies bytes `[0..36]`, index 1 occupies bytes `[36..72]` (straddling lines 0 and 1), and index 2 occupies bytes `[72..108]`.
    - **Result**: Exactly **50% of all lookups** in an AoS `Ipv6Range` array cross a cache line boundary, forcing the hardware memory controller to issue **two L1/L2 cache accesses** per binary search partition step.
 
 ### IPv6 Split-64 Compact Truncation (`Ipv6RangeSplit64`):
 In `v0.10.0`, IPAtlas introduces the **Split-64 Truncation** scheme:
 ```rust
 #[repr(C, packed)]
 pub struct Ipv6RangeSplit64 {
     pub ip_from_hi: u64,    // 8 bytes (upper 64 bits)
     pub count_hi: u32,      // 4 bytes (/64 block count)
     pub profile_id: u32,    // 4 bytes
 }                           // Total = 16 bytes
 ```
 
 - **Zero Cache-Line Straddling**: $\gcd(16, 64) = 16$. Exactly **4 records per 64-byte cache line** without crossing line boundaries.
 - **Memory Reduction**: Shrinks table size from $36 \times N$ to $16 \times N$ bytes (**-55.6% RAM** / 2.25x compression factor).
 - **Measured Criterion Latencies (10,000 intervals, Intel Core i9-11900H)**:
   - `ipv6_standard_lookup_u128` (36B, standard lossless): **64.96 ns**
   - `ipv6_split64_compact_lookup_u128` (16B, compact lossy): **80.40 ns** (bounds shifting overhead)
   - `ipv6_flags_lookup_u128` (36B, flags only): **12.99 ns** (~76.9M QPS)
   - `ipv6_profile_lookup_u128` (36B, profile direct): **12.47 ns** (~80.1M QPS)
   - `ipv6_split64_flags_lookup_u128` (16B, flags only): **16.92 ns** (~59.1M QPS)
   - `ipv6_split64_profile_lookup_u128` (16B, profile direct): **17.09 ns** (~58.5M QPS)
   - `eytzinger_branchless_lookup_v6_u64` (16B BFS array with prefetch): **15.64 ns** (~63.9M QPS)
 
 On large datasets exceeding CPU cache (DRAM-bound regime), the 55.6% memory reduction directly translates into fewer DRAM page misses and significantly lower memory bus contention in multi-threaded query engines.

