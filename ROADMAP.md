# IPAtlas Roadmap

## v0.4.0 — Rust Systems Engine Rewrite [Completed]

**Goal:** Completely replace the Python prototype with a high-performance, memory-safe Rust implementation delivering sub-100ns query latency and streaming compilation.

- [x] Pure-Rust 1D streaming sweep line compiler ($O(N + M)$ execution).
- [x] True zero-copy binary layout using `zerocopy` and `memmap2`.
- [x] Sub-100ns binary search lookup engine over memory-mapped contiguous intervals.
- [x] Bitmask threat categorization (Datacenter, Residential, Proxy, VPN, Tor, Botnet, Spam).
- [x] CLI commands: `build`, `query`, `inspect`, `bench`.

---

## v0.5.0 — Optimization Presets, Cache Alignment & Layout Tiers [Completed]

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

## v0.6.0 — Succinct Data Structures & Elias-Fano Encoding [Completed]

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

## v0.7.0 — Embedded Zstandard & Pipeline Decoupling [Completed]

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

## v0.8.0 — Orthogonal Matrix, SoA Columnar Layout & Flags Fast-Path [Completed]

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

## v0.9.0 — Profile-Only Fast-Path & Empirical Dual-Stack Benchmarks [Completed]

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

## v0.9.1 — Modular Codebase Architecture & Data Compliance [Completed]

**Goal:** Modularize internal architecture to eliminate monolithic source files, harden mmap safety boundaries, and establish official legal compliance and licensing guidelines.

- [x] **Modular Reader Architecture**:
  - Decomposed `src/reader/` into `error.rs`, `buffer.rs`, `dispatch.rs`, and `strings.rs` while retaining 100% API compatibility.
- [x] **Modular CLI Architecture**:
  - Reduced `src/main.rs` to 25 lines, organizing CLI logic into `src/cli/` (`args.rs`, `commands.rs`, `convert.rs`, `bench.rs`).
- [x] **Data Compliance & Licensing Architecture**:
  - Published `docs/DATA_COMPLIANCE.md`: Engine (MIT) vs Data separation, CC BY-SA 4.0 attribution, and GDPR coarse location compliance.

---

## v0.10.0 — IPv6 Split-64 Truncation & Branchless Eytzinger Search [Planned]

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

## v0.11.0 — Hardening, Truth-in-Benchmarking & Core Hygiene [Completed]

**Goal:** Eliminate all adversarial review findings, achieve absolute truth-in-benchmarking, ensure 100% memory soundness, and streamline core search implementations.

- [x] **Truth-in-Benchmarking & Metric Clarity**:
  - Unambiguously separate L1-cache fit (10k) and Production DRAM (5.3M) in all documentation and benchmark tables.
  - Explicitly label multi-threaded metrics as `throughput-equivalent (16T)` to avoid conflation with single-query latency.
  - Fix benchmark miss-bias by testing hit-paths using real IP keys sampled from dataset intervals alongside miss-paths.
  - Clarify Eytzinger BFS and Succinct Elias-Fano as experimental research evaluation benchmarks (not on-disk default).
- [x] **Core Search Consolidation (Subtract-Before-You-Add)**:
  - Collapse 4x duplicated binary search `match TableDispatch` into unified `lookup_raw_v4(ip: u32) -> Option<usize>` helper.
- [x] **Memory Soundness & Undefined Behavior Elimination**:
  - Replace unaligned field accesses in `Ipv6Range` (36B `repr(C, packed)`) with safe `read_unaligned` / struct copying.
- [x] **Error Propagation & Silent Corruption Guards**:
  - Distinguish genuine cache/interval misses (`None`) from internal database corruption errors (OOB profile/string indices).
- [ ] **Pipeline Optimization (`stitch-rs`)**:
  - Eliminate `Instant::now()` and heap allocations (`String`) on high-throughput bogon evaluation paths.
- [x] **Lossy Split-64 Accuracy Disclaimer**:
  - Enforce explicit opt-in contract and add precision notice for sub-`/64` over-approximation.

---

## v0.12.0 — Honest Production-Ready & Ecosystem Integrations [Completed]

**Goal:** Deliver an honest single-node production-ready library and CLI with zero silent failures on corrupted data, thread-safe hot reload, SPI ingestion, and clear boundaries between production search and experimental benchmarks.

- [x] **Strict Corruption vs NotFound Propagation**:
  - Differentiate genuine interval misses (`Ok(None)`) from internal database corruption or tampered metadata (`Err(ReaderError::Corrupted)`).
  - Strict `try_lookup_*` family of methods preventing edge firewalls from silently approving malicious traffic when database sectors are corrupted.
  - Checked arithmetic in compact range intervals rejecting overflowing counts.
- [x] **Dataset Ingestion Service Provider Interface (SPI)**:
  - Extensible `DatasetIngestionAdapter` trait with intermediate `IngestRecordV4` and `IngestRecordV6` models.
  - Native CIDR parsing (`from_cidr`) for custom threat feeds.
- [x] **Thread-Safe Hot-Reload Abstraction**:
  - Lock-free, atomically swappable `HotReloadDatabase` backed by `arc-swap`.
- [x] **Continuous Fuzzing & Resilience Suite**:
  - Differential noise and systematic byte-flip fuzz testing (`tests/test_fuzz_resilience.rs`).
- [x] **Honest Truth-in-Benchmarking & Demotions**:
  - Reconciled all documentation against DRAM latency matrix (193–205 ns production vs 68.7 ns hot-L1).
  - Explicitly demoted Succinct and Eytzinger BFS layouts from production architecture to experimental benchmark-only prototypes.
  - Documented pipeline trade-off: raw lookup is nanosecond hot path; `stitch-rs` adds ~128 ns for security policy traversal.

### Non-Goals for v0.12.0

To maintain absolute architectural honesty and avoid speculative complexity:

- **Eytzinger Search in Production Runtime**: Retained purely as Criterion benchmark prototype; flat binary search remains on-disk format.
- **SIMD /16-LUT**: Not implemented; DRAM bus latency dominates 5.3M record lookup.
- **NUMA-Aware Sharding**: Single-node memory-mapped read-only concurrency via OS page cache is sufficient.
- **Cluster / HA Replication**: Out of scope; replication belongs to infrastructure layers (e.g. S3/k8s atomic file distribution).

---

## v0.13.0 — Universal Drop-In Ecosystem Adapters (90% Market Coverage) [Completed]

**Goal:** Deliver zero-effort drop-in adapters and language clients for 90% of real-world production environments across Rust, Python, Go, C/Nginx, Actix, MaxMind migration, and Kubernetes/DevOps.

- [x] **Web & Service Frameworks**:
  - `adapters/ipatlas-adapter-tower`: Tower Layer/Service & Axum `ClientGeo` request extractor with strict threat blocking.
  - `adapters/ipatlas-adapter-actix`: Actix-web Transform/Service middleware with zero-allocation threat short-circuiting.
  - `adapters/ipatlas-adapter-maxminddb-compat`: Drop-in replacement for official `maxminddb` crate (`Reader::open_readfile` + `reader.lookup::<CityRecord>(ip)`).
- [x] **Foreign Language Bindings (C-ABI First)**:
  - `adapters/ipatlas-adapter-c`: Zero-allocation panic-safe C-ABI shared/static library + `include/ipatlas.h`.
  - `bindings/python/ipatlas`: Pure standard library `ctypes` wrapper (`pip install .` without compiler).
  - `bindings/go/ipatlas`: High-performance `cgo` package wrapping C-ABI.
- [x] **DevOps, Kubernetes & Reverse Proxies**:
  - `ipatlas serve`: Native HTTP microservice / sidecar exposing `/lookup/:ip`, `/healthz`, and `/metrics` (Prometheus).
  - Minimal Dockerfile and production Kubernetes deployment manifest (`deploy/k8s/ipatlas-sidecar.yaml`).
  - Production proxy integration recipes for Nginx Lua FFI, Envoy ExtAuthz, and Caddy (`docs/recipes/PROXIES.md`).
- [x] **Data Ingestion & Migration**:
  - `ipatlas-cli compile --maxmind-blocks ... --maxmind-locations ...`: 1-command migration from GeoLite2 City CSV.

### Non-Goals for Ecosystem Expansion

To prevent maintenance sprawl while maintaining the "Single Source of Truth" rule:

- **Node.js / napi-rs Native Addon**: Out of scope; Node.js applications integrate via the ultra-compact Kubernetes HTTP sidecar (`ipatlas serve`) or standard FFI (`ffi-napi`).
- **Envoy WASM Filter**: Out of scope; Envoy external authorization (`ext_authz`) to the local sidecar provides sub-millisecond evaluation with zero WASM toolchain overhead.
- **Dynamic Language Custom Parsers**: Zero custom database parsing outside Rust core; all language bindings MUST remain thin wrappers around `ipatlas_adapter_c`.

---

## v0.14.0 — Community Gaming Integration: Metamod-P & AMX Mod X Native Module [Planned (No Deadline)]

**Goal:** Provide zero-overhead player geolocation and threat protection for GoldSrc engine dedicated servers (Counter-Strike 1.6, Half-Life) via native Metamod and AMXX native module plugins.

- [ ] **Native C-ABI Metamod Plugin (`ipatlas_mm`)**:
  - Intercept `ClientConnect` / `ClientPutInServer` engine callbacks with zero tickrate degradation.
  - Sub-microsecond player country extraction and proxy/VPN/botnet rejection before game slot assignment.
- [ ] **AMX Mod X Module & Pawn Natives**:
  - `ipatlas_get_country(id, output[], len)`
  - `ipatlas_is_threat(id)`
  - `ipatlas_is_proxy(id)`
  - Direct zero-copy memory lookup without disk I/O during game ticks.

---

## v0.15.0 — Automated Live Feeds & Dynamic Synchronization [Planned (No Deadline)]

**Goal:** Deliver zero-downtime hot database updates from remote URL feeds using atomic pointer swapping.

- [ ] **CLI Scheduled Feed Updater**:
  - `ipatlas update --feed <url> --target <path> --verify-crc`: Downloads and verifies fresh feeds in the background.
- [ ] **Sidecar Atomic Auto-Reload (`ipatlas serve --auto-reload`)**:
  - Integrates `HotReloadDatabase` with `notify` file-watchers to atomically swap in-memory mmap containers on Kubernetes ConfigMap changes without dropping active HTTP connections.

---

## v0.16.0 — Ahead-of-Time Distribution Metadata & 2-Stage Range Lookup [Completed]

**Goal:** Leverage ahead-of-time database compilation to analyze dataset key distribution and inject ultra-compact metadata headers/footers for sub-microsecond zero-copy startup and sub-100ns 2-stage branchless range lookups.

- [x] **Trailing AOT Distribution Footer (`ContainerFooter`)**:
  - Offline baking of the 512 KB 65,536-entry Stage 1 Guide Table directly behind string blobs with 8-byte alignment.
  - Slashes container opening time from **17.6 ms down to 39 µs (-99.8%)** with **0 bytes heap allocation**.
  - 100% backwards compatibility with legacy containers via runtime fallback guide generation.
- [x] **Scrooge 2-Stage Range Lookup Engine**:
  - Deterministic 2-stage hierarchy:
    1. **Stage 1 (L1/L2 Cache Guide-Search)**: $O(1)$ prefix index isolating narrow interval slices ($\le 64$ records).
    2. **Stage 2 (Local Flat Search)**: Branchless `cmov` binary search over contiguous cache-aligned interval slices.
  - Delivers **85.2 ns** full-record lookup and **34.7 ns** flags-only lookup on 5.3M production snapshots.
- [x] **Empirical Benchmark & Validation Stand**:
  - Comprehensive benchmarks across 1,000,000 queries documenting latency, QPS, Rayon multi-threading, and open initialization speed in `docs/BENCHMARKS.md`.

---

## v0.17.0 — Core Modular Decomposition & Refactoring [Planned]

**Goal:** Decompose bloated monolithic files (`mmap_reader.rs` > 1500 LOC, `writer.rs` > 600 LOC) into clean, single-responsibility submodules while strictly preserving zero-cost abstraction invariants and zero-breaking C-ABI/Rust API contracts.

- [ ] **Reader Modular Decomposition (`core/ipatlas-core/src/reader/`)**:
  - `reader/open.rs`: Container validation, magic bytes, version dispatch, and trailing AOT footer extraction.
  - `reader/dispatch.rs`: Internal raw binary search dispatch across all 8 TableDispatch variants (`lookup_raw_v4`, `lookup_raw_v6`).
  - `reader/facade.rs` / `mmap_reader.rs`: Clean public API facade (`lookup_u32`, `lookup_flags_u32`, `lookup_addr`, `is_datacenter`, iterators).
- [ ] **Compiler Modular Decomposition (`core/ipatlas-core/src/compiler/`)**:
  - `compiler/footer.rs`: Dedicated footer emission, alignment padding, and checksum finalization logic extracted from `writer.rs`.
  - `compiler/pools.rs`: String deduplication pool and Last-Value Cache (LVC) isolation.
- [ ] **Architectural & Safety Verification**:
  - Zero performance regression across Criterion microbenchmarks and 5.3M queries.
  - Zero clippy warnings with `-D warnings` and strict enforcement of unsafe safety comments (`// SAFETY:`).

---

## v1.0.0 — Production LTS & Format Freeze [Planned]

**Goal:** Freeze binary container format specification (SemVer 1.0 guarantee), deliver official C-ABI and WASM targets, and publish 100M+ query verification traces.

- [ ] **Binary Format Freeze**:
  - Guarantee forward and backward compatibility across V4 and V5 generation containers.
- [ ] **C-ABI Shared Library & Header**:
  - `libipatlas` with `ipatlas.h` for nginx, HAProxy, Envoy, and game servers.
- [ ] **WebAssembly (WASM) Target**:
  - Compile reader to `wasm32-wasip1` / `wasm32-unknown-unknown` for edge workers (Cloudflare, Fastly).
- [ ] **Production Verification**:
  - 100M+ real-world query traces benchmarked on AMD Ryzen and ARM Neoverse platforms.
