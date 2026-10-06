<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] - 2026-10-06

### Added

- **CRC32 Pre-Flight Verification Constructor (open_verified**:
  - Added explicit IpAtlasReader::open_verified() constructor that computes and verifies CRC32 checksums upon opening Generation V5 containers.
  - Keeps standard IpAtlasReader::open() strictly zero-copy and header-only (nanosecond opening time) without forcing I/O-intensive checksum validation by default.

### Refactored

- **Core Query Dispatch Consolidation**:
  - Unified IPv4 binary search logic across all 8 TableDispatch variants into a single canonical lookup_raw_v4(&self, ip: u32) -> Option<(u32, u32, usize)> in mmap_reader.rs.
  - Converted lookup_u32, lookup_flags_u32, lookup_country_code_u32, and lookup_profile_u32 into thin, zero-cost projections over lookup_raw_v4, eliminating over 300 lines of duplicated binary search logic and preventing branch divergence.

### Fixed

- **Memory Soundness in Packed IPv6 Structures**:
  - Implemented safe, unaligned copy accessors (ip_from(), ip_to(), profile_id()) using ddr_of!(...).read_unaligned() on #[repr(C, packed)] struct Ipv6Range.
  - Completely eliminated unaligned pointer reference warnings and potential UB during binary search and bounds checks in mmap_reader.rs.
- **IPv4-Mapped IPv6 Lookup Ordering**:
  - Hot-path optimization in lookup_addr: check ::ffff:0:0/96 prefix via  o_ipv4_mapped() first, avoiding ~23 cold binary search misses across the IPv6 table for IPv4-mapped addresses.
- **Truth-in-Benchmarking & Metric Clarity**:
  - Re-labeled multi-threaded batch throughput in CLI benchmarks (src/cli/bench.rs) to explicit Throughput-Eq (ns/query) to avoid conflating aggregate throughput (/\text{QPS}$) with single-query latency.
  - Separated true interval hit-path benchmarking from miss-path testing in Criterion suites (enches/lookup_bench.rs).

### Documentation

- **Roadmap Realignment**:
  - Realined ROADMAP.md: formalized 0.11.0 as Hardening, Truth-in-Benchmarking & Core Hygiene release, while shifting ecosystem web framework drop-in integrations to 0.12.0.

## [0.10.0] - 2026-10-05

### Added

- **IPv6 Split-64 Opt-In Lossy Compression (`Ipv6RangeSplit64`)**:
  - Implemented 16-byte `/64` compact record format (`ip_from_hi: u64`, `count_hi: u32`, `profile_id: u32`) packing 4 entries per 64-byte CPU cache line with zero straddling (-55.6% memory footprint vs 36-byte records).
  - Explicit lossy opt-in contract via `--split64-v6` / `-O split64-v6` (`OptimizationConfig::split64_v6 = true`), keeping lossless 36-byte `Ipv6Range` as the safe default for IPv6 even when `--family compact` is specified.
  - Documented over-approximation contract on sub-`/64` intervals and added verification tests for boundary guarantees.
- **Empirical IPv6 Microbenchmarks (Intel Core i9-11900H)**:
  - Documented comprehensive Criterion metrics in `docs/BENCHMARKS.md`:
    - `ipv6_standard_lookup_u128` (36B, lossless): **64.96 ns**
    - `ipv6_flags_lookup_u128` (36B, flags only): **12.99 ns** (~76.9M QPS)
    - `ipv6_profile_lookup_u128` (36B, profile direct): **12.47 ns** (~80.1M QPS)
    - `ipv6_split64_flags_lookup_u128` (16B, flags only): **16.92 ns** (~59.1M QPS)
    - `ipv6_split64_profile_lookup_u128` (16B, profile direct): **17.09 ns** (~58.5M QPS)
- **Experimental Branchless Eytzinger BFS Layout**:
  - Added cache-friendly Eytzinger array layout and search in benchmarks (`compiler::eytzinger`) with `_mm_prefetch`, clocking **13.55 ns** (IPv4) and **15.64 ns** (IPv6).
- **Web Framework Integration Guide**:
  - Added [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md) providing battle-tested recipes for Axum (`Extension`), Actix-Web, Tower middleware, and zero-downtime hot reloading with `arc-swap`.

### Refactored

- **Uncompromising Generation and Protocol Taxonomy**:
  - Decoupled container format generations from IP protocol families across all domain models:
    - `RangeV4` -> `Ipv4Range`, `RangeV4Compact` -> `Ipv4RangeCompact`
    - `RangeV6` -> `Ipv6Range`, `Ipv6RangeSplit64`
    - `ProfileV4` -> `ProfileGen4`
    - `HeaderV4` -> `HeaderGen4`, `HeaderV5` -> `HeaderGen5`
    - Version constants renamed to `VERSION_GEN4_*` and `VERSION_GEN5_*`.
- **Pre-Release Version Bump**:
  - Bumped crate version to `0.10.0`.

## [0.9.1] - 2026-10-05

### Added

- **Data Compliance & Licensing Architecture**:
  - Added official guide [`docs/DATA_COMPLIANCE.md`](docs/DATA_COMPLIANCE.md) clarifying MIT engine boundaries, CC BY-SA 4.0 attribution requirements for IP2Location LITE, commercial feed handling, and GDPR/CCPA coarse location compliance.

### Refactored

- **Modular Reader Architecture**:
  - Decomposed monolithic `mmap_reader.rs` into specialized submodules under `src/reader/`:
    - `error.rs`: Centralized `ReaderError` enum with exhaustive variants (`InvalidMagic`, `UnsupportedVersion`, `CrcMismatch`, `OutOfBounds`, `Utf8Error`, `LayoutMismatch`).
    - `buffer.rs`: `StorageBuffer` abstraction unifying memory-mapped files and heap byte vectors with sound byte slice access.
    - `dispatch.rs`: `TableDispatch` handling orthogonal runtime dispatch across AoS / SoA and V4 / V5 table types.
    - `strings.rs`: `StringTableRef` encapsulating zero-copy UTF-8 resolution and slice bounds verification.
- **Modular CLI Command Architecture**:
  - Modularized `src/main.rs` down to a lightweight 25-line entrypoint, migrating implementation to `src/cli/`:
    - `args.rs`: Structured Clap CLI definitions (`Cli`, `Commands`, subcommand argument structs).
    - `commands.rs`: Compilation, inspection, and lookup workflows.
    - `convert.rs`: Offline database AoS <-> SoA repack utility.
    - `bench.rs`: Benchmark execution harness.

## [0.9.0] - 2026-10-05

### Added

- **Profile-Only Direct Fast-Path API**:
  - Added zero-allocation accessors returning the raw 20-byte normalized [`ProfileV4`] metadata struct directly:
    - `IpAtlasReader::lookup_profile_u32(ip: u32) -> Option<&ProfileV4>`
    - `IpAtlasReader::lookup_profile_u128(ip: u128) -> Option<&ProfileV4>`
    - `IpAtlasReader::lookup_profile_addr(ip: IpAddr) -> Option<&ProfileV4>`
    - `IpAtlasReader::lookup_profile(ip: impl Into<IpAddr>) -> Option<&ProfileV4>`
  - Allows consumers to instantly retrieve coordinates (`latitude()`, `longitude()`), ASN (`asn`), flags (`flags`), and ISO country code (`country_code()`) in **13.6–14.1 ns** without parsing or allocating string records.
- **IPv6 Dual-Stack (128-bit) Empirical Benchmarks & Straddling Analysis**:
  - Extended Criterion testbed in `benches/lookup_bench.rs` with 10,000 IPv6 ranges:
    - `ipv6_standard_lookup_u128`: **68.85 ns** (36-byte packed `RangeV6`).
    - `ipv6_flags_lookup_u128`: **14.48 ns**.
    - `ipv6_profile_lookup_u128`: **13.64 ns**.
  - Documented 36-byte cache-line straddling phenomenon in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md), establishing baseline metrics for the planned v0.10.0 128-bit SoA container.
- **Zero-Allocation Pipeline Outcome Views (`stitch-rs`)**:
  - Added `LookupOutcomeRef<'a>` in `pipeline` module for borrowing underlying `GeoRecordRef<'a>` directly from kernel mmap buffers, eliminating unwanted 4-string heap allocation penalty on the pipeline hot path.
- **CLI Image Conversion Utility**:
  - Added `ipatlas convert <input> <output> --layout <soa|aos>` to repack databases between AoS and SoA columnar layouts in sub-50ms without re-compiling raw CSV sources.

### Changed

- Updated version to `0.9.0`.
- Documented comprehensive empirical benchmarks in `docs/BENCHMARKS.md` and updated `README.md` matrix with both 5.3M DRAM and 10k L1 cache-fit measurements.

## [0.8.0] - 2026-10-05

### Added

- **Orthogonal 3D Format Matrix (`Generation` x `Family` x `Layout`)**:
  - Decoupled physical container dimensions into explicit types: `ContainerVersion` (V4 / V5), `RecordFamily` (Standard / Compact), and `StorageLayout` (AoS / SoA).
  - Explicit container version constant matrix:
    - V4 Standard: AoS = `0x0400` (`VERSION_V4_STANDARD`), SoA = `0x0402` (`VERSION_V4_STANDARD_SOA`)
    - V4 Compact: AoS = `0x0401` (`VERSION_V4_COMPACT`), SoA = `0x0403` (`VERSION_V4_COMPACT_SOA`)
    - V5 Standard: AoS = `0x0005` (`VERSION_V5_STANDARD`), SoA = `0x0502` (`VERSION_V5_STANDARD_SOA`)
    - V5 Compact: AoS = `0x0501` (`VERSION_V5_COMPACT`), SoA = `0x0503` (`VERSION_V5_COMPACT_SOA`)
  - Added CLI options `--family <compact|standard>` and `--layout <aos|soa>` alongside compiler optimization config `-O soa/aos/compact/standard`.
- **Structure of Arrays (SoA) Storage Layout**:
  - Implemented columnar storage layout for interval tables: splits record structs into contiguous homogeneous arrays (`soa_ip_from`, `soa_count` / `soa_ip_to`, `soa_profile_id`).
  - Achieves 100% cache line utilization during binary search (16 `u32` keys per 64-byte L1 cache line without fetching unwanted metadata fields).
  - Accelerates random IPv4 lookup latency down to **15.4 ns** on 10k L1 cache-fit microbenchmarks and **84.2 ns** on 5.3M production snapshots.
- **Flags-Only Fast Path API**:
  - Added zero-allocation, stringless query primitives for high-throughput packet filters and firewalls:
    - `IpAtlasReader::lookup_flags_u32(ip: u32) -> Option<GeoFlags>`
    - `IpAtlasReader::is_threat_u32(ip: u32) -> bool`
    - `IpAtlasReader::is_proxy_u32(ip: u32) -> bool`
    - `IpAtlasReader::is_datacenter_u32(ip: u32) -> bool`
    - `IpAtlasReader::lookup_country_code_u32(ip: u32) -> Option<&str>`
  - Bypasses string blob offset scanning and UTF-8 verification, resolving security and threat rules at **11.88M QPS** (2.5x faster than full record queries).
- **Table Layout Dispatch Hoisting**:
  - Hoisted layout branching (`is_soa`, `is_compact`, version decoding) to file initialization via `TableDispatch` descriptor enum.
  - Eliminated per-query `ref_from_bytes` slice revalidations and cascading branches across all accessors.
- **OS Kernel Page Advice (`madvise` & `warmup`)**:
  - Automatically advises OS kernel via `libc::madvise(MADV_RANDOM)` on file open on Unix targets to tune virtual memory readahead for random binary searches.
  - Added `IpAtlasReader::warmup()` providing `libc::madvise(MADV_WILLNEED)` kernel advice on Unix to request memory page prefetching prior to serving live edge traffic.
- **Scientifically Grounded Blocked-Zstandard Chunk Sizing Helper & Microbenchmark**:
  - Added `calculate_chunk_records_count(record_size, target_chunk_bytes)` in `models::optimization`.
  - Evaluated chunk boundary trade-offs across 4KB, 16KB, 64KB, and 256KB in Criterion benchmarks, measuring **692 MB/s** sustained decompression at 64 KB L2-aligned chunks to prepare the ground for future blocked-container streaming layouts (while the monolithic `EMBEDDED_ZSTD` container remains unchanged in v0.8.0).

## [0.7.0] - 2026-10-04

### Added

- **Embedded Compression Container Architecture (`EMBEDDED_ZSTD`)**:
  - Added optional embedded Zstandard payload compression (`zstd-19`) inside binary `.bin` database files.
  - Specified physical container layout and header bitmask flag: `HEADER_FLAG_EMBEDDED_ZSTD = 0x0004` encoded in `HeaderV5::reserved`.
  - Transparent in-memory decompression in `IpAtlasReader`: keeps uncompressed 80-byte `HeaderV5` on disk, transparently decodes compressed payload into an anonymous memory buffer upon opening, preserving exact CRC32 verification and sub-100ns lookup speed with zero subsequent allocations.
  - Added `--embedded-zstd` (alias `--zstd`) flag to `ipatlas compile` and `-O embedded-zstd` optimization rule.
  - Added `StorageBuffer { Mmap(Mmap), Memory(Vec<u8>) }` abstraction in `IpAtlasReader` providing transparent `Deref<Target = [u8]>` zero-copy views.
  - Made `zstd` an optional dependency gated under `feature = "embedded-zstd"`: preserves minimal zero-dependency reader builds (`--no-default-features`), returning an actionable error (`"rebuild with embedded-zstd"`) when an `EMBEDDED_ZSTD` binary is opened without the feature.
  - Pinned `stitch-rs` git dependency to immutable commit revision `rev = "30b0fe64a0eed2f41c668618b15586ed865433ac"`, satisfying audit reproducibility requirements.
- **Benchmark Hardware Testbed & Reproduction Conditions (`docs/SPECIFICATION.md`, `README.md`)**:
  - Added formal benchmark testbed environment details: Intel Core i7 / AMD Ryzen 9 x86_64, AVX2 enabled, 32KB L1d cache, Criterion.rs 0.5.1 with 1,000,000 warmups, 1024 pseudo-random queries to defeat branch prediction.
  - Documented dataset lineage: 5,318,878 intervals post-merge snapshot (`IP2Location DB5` + `IP2Proxy PX10`, SHA-256: `9a8f4c2e...`) vs raw 7.9M uncoalesced multi-provider catalogs.
  - Formally codified `V5-Succinct` as an **Experimental** research tier in layout matrices, establishing `V4/V5-Compact` as the recommended production tier.
- **Succinct Stream Incompressibility Specification (`docs/SPECIFICATION.md`)**:
  - Documented Section 5.3 clarifying theoretical and empirical incompressibility of Elias-Fano succinct streams ($H \approx 1.0\text{ bit/bit}$).
  - Codified the invariant that `V5-Succinct` data must be distributed strictly as raw binaries, whereas embedded Zstd is designated for standard/compact layouts with unquantized metadata.

## [0.6.0] - 2026-10-04

### Added

- **Quasi-Succinct Elias-Fano Compression Core (`V5-Succinct`)**:
  - Implemented monotonic Elias-Fano interval boundary encoder in `compiler::succinct::SuccinctIntervalTable`.
  - Reaches **18.19 MB** total active in-memory table footprint on 5.3M production database (**$1.03 \times H_{\text{raw}}$**, reaching ~100% of the mathematical Shannon entropy limit).
  - Delivers **353.8 ns** single-query latency (measured via Criterion benchmark `succinct_elias_fano_lookup`), outperforming MaxMind MMDB by 3.1x while saving 84.2% RAM.
  - Added physical production verification suite in `tests/verify_succinct_production.rs` confirming real-data compression on 5,318,878 intervals.
- **Hardware Efficiency Metric & MaxMind MMDB Benchmark**:
  - Introduced hardware efficiency product: $P = \text{RAM (MB)} \times \text{Latency (ns)}$.
  - Confirmed `V4-Compact` as global hardware sweet spot ($2,515\text{ MB}\cdot\text{ns}$, **50.3x more efficient than MaxMind MMDB**).
- **Formal Binary Specification (`docs/SPECIFICATION.md`)**:
  - Documented physical binary memory layouts across all three tiers: `Standard` (12B), `Compact` (8B), and `Succinct` (~2.8B).
  - Formalized mathematical grounding of interval entropy and Zipfian profile packing.
- **Composable Compiler Adapters (StateFS-style)**:
  - Added `compiler::adapters` module with isolated, zero-cost monomorphic stream and topology adapters.
  - Added `CoalesceAdapter`, `LossyCoordsAdapter`, `CompactRangePacker`, and fluent `CompilerStreamExt` trait.
  - Isolated adapter test suite in `tests/test_adapters.rs`.

## [0.5.0] - 2026-10-04

### Added

- **Monomorphic U-Cycle Execution Pipeline (`stitch-rs`)**:
  - Integrated `stitch-rs` as the core operational execution model for lookups.
  - Implemented `BogonFilterLayer`: short-circuits private LAN (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`), loopback (`127.0.0.0/8`, `::1`), link-local, multicast, and IPv6 ULA (`fc00::/7`) directly on the descent stage in ~1.5 ns without invoking binary search or disk mmap accesses.
  - Implemented `ThreatPolicyLayer`: enforces threat intelligence rejection (proxies, VPNs, Tor exit nodes, botnets, spam networks) on the ascent stage.
  - Implemented `TelemetryLayer`: measures high-resolution latency and aggregates execution metrics (`dispatches`, `bogon_short_circuits`, `threat_rejections`).
  - Added `IpAtlasTerminal`: zero-copy resolution terminal mapping into borrowed mmap slices.
  - Added `IpAtlasPipelineExt` trait extending `IpAtlasReader` with `standard_pipeline()` and `query_pipeline()`.
  - Added `StandardLookupPipeline` concrete type alias eliminating trait object overhead.
  - Comprehensive integration test suite in `tests/test_pipeline.rs`.

## [0.4.0] - 2026-10-02

### Added

- **Complete Rust Engine Rewrite**: Transitioned the entire IPAtlas codebase from the Python prototype (PoC) into a production-grade, memory-safe, systems-level library and CLI in Rust.
- **Format V4.1 Compact (8-byte ranges)**: Added alternative compact layout (`RangeV4Compact`: `ip_from: u32, count: u16, profile_id: u16`) via `--layout compact` or `-O compact-ranges`. Shrinks range table size by **33.3%** and fits 8 records per 64-byte CPU cache line.
- **100% Sound Safe Zero-Copy Reader**: Completely eliminated self-referential `unsafe &'static` slices in favor of verified `zerocopy::FromBytes` bounds and on-the-fly slice mapping from `memmap2::Mmap`.
- **Sub-100ns Lookup Performance**: Benchmarked at **66.6 nanoseconds** per lookup (~**15,000,000 queries/second** single-threaded) via Criterion benchmarks — a **~100x throughput leap** over Python.
- **Realistic Random & Cache-Miss Benchmarks**: Enhanced benchmark suite measuring cold random uniform IPv4 queries alongside hot L1 lookups.
- **Compiler Optimization Pipeline (`-O`)**:
  - `-O0`: Raw pass-through intervals without coalescing.
  - `-O1` (Default): Safe lossless cascade interval coalescing, profile deduplication, and empty string pruning.
  - `-O2`: `-O1` + case/whitespace string normalization.
  - `-O3`: `-O2` + unbiased symmetric coordinate quantization (~10km resolution) for maximum edge reduction.
  - Fine-grained semantic flags: `-O coalesce`, `-O lossy-coords`, `-O normalize-strings`, `-O compact-ranges`.
- **Atomic File Persistence & Strict Validation**: Compiler writes to temporary files before atomic rename with disk synchronization (`sync_all`). `HeaderV4::validate` enforces strict non-overlapping sequential boundaries across profile and string blob tables.
- **Streaming 1D-Sweep Line Compiler**: $O(N + M)$ single-pass input stream bounded by output table memory (~115 MB for 8M rows), eliminating multi-gigabyte Python heap explosion.
- **Zero Data Loss Guarantee**: Preserves disjoint threat ranges from IP2Proxy outside IP2Location Geo coverage.
- **Native Embedded Compression**: Direct in-process Zstandard compression (level 19) and Gzip compression via `zstd` and `flate2`, eliminating external subprocess binaries.
- **Modular Cargo Architecture**: Reader-only client mode (`--no-default-features`) compiles in under 1 second with minimal dependencies (`memmap2`, `zerocopy`, `memchr`).
- **Benchmark Suite & Tests**: Full integration test suite (`tests/`) and Criterion benchmarks (`benches/lookup_bench.rs`).

### Changed

- **Python PoC Archival**: The initial Python prototype scripts and tests have been preserved under `poc/python/` as the historical proof-of-concept phase.
- **CI/CD Quality Gates**: Upgraded GitHub Actions workflow to native Rust test runner with pedantic clippy enforcement and format checks.

## [0.3.0] - 2026-10-01

### Added

- **Presets & Feature Masks**: Added `--preset` (`full`, `city`, `firewall`, `country`, `threats`) and `--features` bitmask compiler options. Unused metadata fields are masked and adjacent intervals coalesce on the fly, reducing database size down to **5.6 MB** binary (~1.2 MB `.zst`, **233x reduction**) for pure country geo-blocking.

## [0.2.0] - 2026-10-01

### Added

- **Profile ID Normalization (Format V4)**: Decoupled IP ranges from repeated metadata. Replaces 28-byte inline records with compact 12-byte ranges (`from`, `to`, `profile_id`) and a dedicated 20-byte Profile Table.
- **Universal Dataset Support**: Dynamic column detection for all IP2Location LITE/Commercial databases (`DB1`, `DB3`, `DB5`, `DB11`) and IP2Proxy (`PX1` - `PX12`).
- **Zstandard Distribution (`.zst`)**: Automated compression using Zstandard level 19, reducing distribution size by **26.8x** (740 MB CSV down to 27.6 MB).
- **Flexible CLI Arguments**: Added `--geo` (or `--db`) and `--proxy` (or `--px`) flags to compiler CLI.

### Changed

- **Rebranding**: Project renamed from `grlg-geo` to `ipatlas`. CLI entry point renamed to `ipatlas`.
- **Binary Header**: Magic updated to `b'ATLS'` (with backward compatibility for `b'GRLG'`).
- **Memory Footprint**: Reduced uncompressed binary size by **55.2%** (from 214.1 MB down to 95.9 MB for unified full global dataset).

### Deprecated / Compatibility

- `GrlgReader` alias preserved for backward compatibility with `IpAtlasReader`.
- Legacy CLI flags (`--db5`, `--px10`) retained as aliases.

## [0.1.0] - 2026-09-29

### Added

- Initial release of zero-copy binary GeoIP and Proxy/VPN threat database compiler and reader.
- Sub-microsecond binary search over memory-mapped intervals (`mmap`).
- 1D streaming interval sweep for disjoint Geolocation (DB5) and Threat Intelligence (PX10) CSVs.
- Bitflag threat classification for hosting, proxies, VPNs, botnets, and residential networks.
