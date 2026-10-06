# IPAtlas Roadmap

## v0.4.0 — Rust Systems Engine Rewrite ✅

**Goal:** Completely replace the Python prototype with a high-performance, memory-safe Rust implementation delivering sub-100ns query latency and streaming compilation.

- [x] Pure-Rust 1D streaming sweep line compiler ($O(N + M)$ execution).
- [x] True zero-copy binary layout using `zerocopy` and `memmap2`.
- [x] Sub-100ns binary search lookup engine over memory-mapped contiguous intervals.
- [x] Bitmask threat categorization (Datacenter, Residential, Proxy, VPN, Tor, Botnet, Spam).
- [x] CLI commands: `build`, `query`, `inspect`, `bench`.

---

## v0.5.0 — Optimization Presets, Cache Alignment & Layout Tiers ✅

**Goal:** Introduce optimization levels, semantic coalescing, cache-aligned compact layouts, and formal Shannon entropy benchmarking.

- [x] **Layout Tiers**:
  - `V4-Standard` (12-byte `RangeV4`) with universal 32-bit profile IDs.
  - `V4-Compact` (8-byte `RangeV4Compact`) packing 8 records per 64-byte CPU cache line (-32.4% RAM).
- [x] **Optimization Levels**:
  - `-O1`: Semantic coalescing of identical adjacent profiles.
  - `-O2`: String pool normalization and whitespace trimming.
  - `-O3`: Symmetric coordinate quantization (reducing floating point noise).
- [x] **Presets**:
  - `--preset all`: Full precision metadata.
  - `--preset firewall`: Drops City/Coords to maximize interval coalescing (~7.9 MB table).
  - `--preset country`: Country and threat flags only (~5.6 MB table).
- [x] **Data Integrity**: Integrated CRC32 checksum validation across file headers and sections.

---

## v0.6.0 — Succinct Data Structures & Elias-Fano Encoding ✅

**Goal:** Implement succinct monotonic bitvectors reaching near-theoretical Shannon entropy limits for memory-constrained and embedded environments.

- [x] **Elias-Fano Monotone Sequence Encoder**:
  - Split 32-bit endpoint integers into high-bit unary bucket representations and low-bit arrays.
  - Constant-time $O(1)$ `select` bitvector primitives.
- [x] **`V5-Succinct` Layout Tier**:
  - Cuts database RAM usage down to ~17.8 MB on full 5.3M production datasets.
  - Trade-off formalization: ~353 ns lookup latency vs ~17.8 MB footprint.
- [x] **Formal Benchmark Stand Documentation**:
  - Documented reproducibility testbed (AMD Ryzen 9 / Linux 6.x / Criterion).

---

## v0.7.0 — Embedded Zstandard & Pipeline Decoupling ✅

**Goal:** Enable native in-container Zstd compression for compressed disk distribution without double compression overhead, decouple optional dependencies, and stabilize the supply chain.

- [x] **Embedded Zstd Compression (`--compress zstd`)**:
  - Stores compressed profile payload directly within the `.bin` container header flag.
  - Transparent in-memory decompression on open without modifying disk contents.
- [x] **Zero-Overhead Feature Isolation**:
  - Made `zstd` optional behind `embedded-zstd` feature.
  - Reader-only builds (`--no-default-features`) compile with zero heavy compression dependencies.
- [x] **Supply Chain & Audit Stabilization**:
  - Pinned `stitch-rs` Git revision (`rev = "30b0fe64..."`).
  - Added `deny.toml` configuration and CI audit checks (`cargo-audit`, `cargo-deny`).
- [x] **Monomorphic U-Cycle Pipeline (`stitch-rs`)**:
  - Bogon short-circuiting on descent (~1.5 ns).
  - Security policy enforcement on ascent.

---

## v0.8.0 — Orthogonal Matrix, SoA Columnar Layout & Flags Fast-Path ✅

**Goal:** Decouple binary format dimensions into an orthogonal 3D matrix (`Generation` x `Family` x `Layout`), implement Structure of Arrays (SoA) layout for high cache utilization, and provide zero-allocation security filter APIs.

- [x] **Orthogonal 3D Format Matrix**:
  - Independent dimensions: `ContainerVersion` (V4/V5), `RecordFamily` (Standard/Compact), `StorageLayout` (AoS/SoA).
  - Explicit container version constant matrix (`0x0400`..`0x0503`).
- [x] **Structure of Arrays (SoA) Layout**:
  - Columnar interval tables with 100% cache-line utilization (16 `u32` keys per 64-byte L1 cache line).
  - Reduced random lookup latency down to **15.4 ns** (L1 cache-fit) and **84.2 ns** (5.3M production snapshot).
- [x] **Flags-Only Query Primitives**:
  - Stringless zero-allocation fast-paths: `lookup_flags_u32`, `is_threat_u32`, `is_proxy_u32`, `is_datacenter_u32`, `lookup_country_code_u32`.
  - Achieves **11.88M QPS** for firewall packet inspection.

---

## v0.9.0 — Profile-Only Fast-Path & Empirical Dual-Stack Benchmarks ✅

**Goal:** Expose direct metadata fast-paths for stitch-rs integration, conduct empirical 128-bit IPv6 performance analysis, and implement offline AoS <-> SoA database conversion.

- [x] **Profile-Only Fast-Path API**:
  - Direct 20-byte metadata struct access (`lookup_profile_u32`, `lookup_profile_u128`, `lookup_profile_addr`) in **13.6–14.1 ns** without string allocations.
- [x] **IPv6 Empirical Benchmarks & Straddling Analysis**:
  - Extended Criterion test suite for 128-bit intervals (68.85 ns full record, 13.64 ns profile-only).
  - Quantified 36-byte cache-line straddling phenomenon in `docs/BENCHMARKS.md`.
- [x] **Zero-Allocation Pipeline Views (`stitch-rs`)**:
  - Added `LookupOutcomeRef` for borrowing strings directly from mmap buffers.
- [x] **CLI Image Conversion Utility**:
  - Added `ipatlas convert` to repack databases between AoS and SoA columnar layouts in sub-50ms.

---

## v0.9.1 — Modular Codebase Architecture & Data Compliance ✅

**Goal:** Modularize internal architecture to eliminate monolithic source files, harden mmap safety boundaries, and establish official legal compliance and licensing guidelines.

- [x] **Modular Reader Architecture**:
  - Decomposed `src/reader/` into `error.rs`, `buffer.rs`, `dispatch.rs`, and `strings.rs` while retaining 100% API compatibility.
- [x] **Modular CLI Architecture**:
  - Reduced `src/main.rs` to 25 lines, organizing CLI logic into `src/cli/` (`args.rs`, `commands.rs`, `convert.rs`, `bench.rs`).
- [x] **Data Compliance & Licensing Architecture**:
  - Published `docs/DATA_COMPLIANCE.md`: Engine (MIT) vs Data separation, CC BY-SA 4.0 attribution, and GDPR coarse location compliance.

---

## v0.10.0 — IPv6 Split-64 Truncation & Branchless Eytzinger Search 📝 Planned

**Goal:** Eliminate 128-bit cache-line straddling, compress IPv6 entries down to 16 bytes, and introduce branchless Eytzinger array search.

- [x] **IPv6 Split-64 Range Truncation**:
  - Truncate IPv6 search keys to upper 64 bits (`u64`), shrinking packed records from 36B to 16B (`Ipv6RangeSplit64`, 4 entries per 64B cache line, zero straddling).
- [x] **Branchless Eytzinger Search (BFS Array)**:
  - Cache-friendly array layout with `_mm_prefetch` for predictable latency and elimination of branch mispredictions (13.5 ns IPv4 / 16.3 ns IPv6).
- [x] **Taxonomy & Architecture Formalization**:
  - Strict decoupling of container generations (`Gen4`, `Gen5`) from IP protocols (`Ipv4`, `Ipv6`).
  - Elimination of legacy aliases in favour of explicit domain types.
- [x] **Comprehensive Pre-Release Documentation Suite**:
  - Author `docs/INTEGRATION_GUIDE.md` covering web framework middlewares (Actix, Axum, Tower), zero-downtime hot-reloading, and preset sizing recipes.
- [x] **Empirical Verification on Dual-Stack Benchmark Testbed**:
  - Benchmarked Split-64 vs uncompressed 36-byte intervals on Criterion testbed (64.96 ns standard vs 80.40 ns compact full record, 12.47 ns standard vs 17.09 ns compact direct profile lookup).
  - Validated branchless Eytzinger BFS layout for IPv6 at 15.64 ns.

---

## v0.11.0 — Hardening, Truth-in-Benchmarking & Core Hygiene 🚧 In Progress

**Goal:** Eliminate all adversarial review findings, achieve absolute truth-in-benchmarking, ensure 100% memory soundness, and streamline core search implementations.

- [ ] **Truth-in-Benchmarking & Metric Clarity**:
  - Unambiguously separate L1-cache fit (10k) and Production DRAM (5.3M) in all documentation and benchmark tables.
  - Explicitly label multi-threaded metrics as `throughput-equivalent (16T)` to avoid conflation with single-query latency.
  - Fix benchmark miss-bias by testing hit-paths using real IP keys sampled from dataset intervals alongside miss-paths.
  - Clarify Eytzinger BFS and Succinct Elias-Fano as experimental research evaluation benchmarks (not on-disk default).
- [ ] **Core Search Consolidation (Subtract-Before-You-Add)**:
  - Collapse 4x duplicated binary search `match TableDispatch` into unified `lookup_raw_v4(ip: u32) -> Option<usize>` helper.
- [ ] **Memory Soundness & Undefined Behavior Elimination**:
  - Replace unaligned field accesses in `Ipv6Range` (36B `repr(C, packed)`) with safe `read_unaligned` / struct copying.
- [ ] **Error Propagation & Silent Corruption Guards**:
  - Distinguish genuine cache/interval misses (`None`) from internal database corruption errors (OOB profile/string indices).
- [ ] **Pipeline Optimization (`stitch-rs`)**:
  - Eliminate `Instant::now()` and heap allocations (`String`) on high-throughput bogon evaluation paths.
- [ ] **Lossy Split-64 Accuracy Disclaimer**:
  - Enforce explicit opt-in contract and add precision notice for sub-`/64` over-approximation.

---

## v0.12.0 — Ecosystem Drop-In Integrations & Generic Ingestion 📝 Planned

**Goal:** Turn IPAtlas into an effortless drop-in middleware for Rust web frameworks and harden mmap parsing against malicious corruption.

- [ ] **Web Framework Middlewares**:
  - `ipatlas-tower` / `ipatlas-axum` crate providing plug-and-play client geolocation and threat blocking layers.
  - Zero-copy request extensions with ergonomic extractor primitives.
- [ ] **Generic CIDR/Range Ingestion & SPI/Vendor Adapters**:
  - Decouple vendor formats (MaxMind GeoLite2, DB-IP, custom enterprise feeds) via pluggable SPI adapters.
- [ ] **Continuous Fuzzing Suite**:
  - `cargo-fuzz` harness targeting malformed headers, invalid string offsets, and corrupted interval tables.
- [ ] **Thread-Safe Hot-Reload Abstraction**:
  - Background atomic swapping of mmap database handles without dropped queries.

---

## v1.0.0 — Production LTS & Format Freeze 📝 Planned

**Goal:** Freeze binary container format specification (SemVer 1.0 guarantee), deliver official C-ABI and WASM targets, and publish 100M+ query verification traces.

- [ ] **Binary Format Freeze**:
  - Guarantee forward and backward compatibility across V4 and V5 generation containers.
- [ ] **C-ABI Shared Library & Header**:
  - `libipatlas` with `ipatlas.h` for nginx, HAProxy, Envoy, and game servers.
- [ ] **WebAssembly (WASM) Target**:
  - Compile reader to `wasm32-wasip1` / `wasm32-unknown-unknown` for edge workers (Cloudflare, Fastly).
- [ ] **Production Verification**:
  - 100M+ real-world query traces benchmarked on AMD Ryzen and ARM Neoverse platforms.
