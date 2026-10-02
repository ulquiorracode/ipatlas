<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-10-02

### Added

- **Complete Rust Engine Rewrite**: Transitioned the entire IPAtlas codebase from the Python prototype (PoC) into a production-grade, memory-safe, systems-level library and CLI in Rust.
- **Sub-100ns Lookup Performance**: Achieved **66.6 nanoseconds** per lookup (**~15,000,000 queries/second** single-threaded) via Criterion benchmarks — a **~100x throughput leap** over Python.
- **Zero-Allocation Hot Path**: Added `GeoRecordRef<'a>` and `lookup_u32`, enabling true zero-copy inspection directly from kernel mmap page cache using `zerocopy`, `memmap2`, and SIMD `memchr`.
- **Compiler Optimization Pipeline (`-O`)**:
  - `-O0`: Raw pass-through intervals without coalescing.
  - `-O1` (Default): Lossless cascade interval coalescing, profile deduplication, and empty string pruning.
  - `-O2`: `-O1` + case/whitespace string normalization.
  - `-O3`: `-O2` + lossy coordinate quantization (~10km resolution) for maximum edge reduction.
  - Fine-grained semantic flags: `-O coalesce`, `-O lossy-coords`, `-O normalize-strings`, `-O collapse-threats`.
- **Streaming 1D-Sweep Line Compiler**: $O(N + M)$ single-pass sweep with $O(1)$ working memory, eliminating multi-gigabyte RAM allocation during large dataset compilation.
- **Zero Data Loss Guarantee**: Fixed boundary sweep behavior so disjoint PX threat ranges outside Geo coverage are completely preserved.
- **Native Embedded Compression**: Direct in-process Zstandard compression (level 19) and Gzip compression via `zstd` and `flate2`, eliminating external subprocess binaries.
- **Modular Cargo Architecture**: Reader-only client mode (`--no-default-features`) compiles in under 1 second with minimal dependencies (`memmap2`, `zerocopy`, `memchr`).
- **Benchmark Suite & Tests**: Full integration test suite (`tests/`) and Criterion benchmarks (`benches/lookup_bench.rs`).

### Changed

- **Python PoC Archival**: The initial Python prototype scripts and tests have been preserved under `poc/python/` as the historical proof-of-concept phase.
- **CI/CD Quality Gates**: Upgraded GitHub Actions workflow to native Rust test runner with pedantic clippy enforcement and format checks.

## [0.3.0] - 2026-10-01

### Added

- **Profile ID Normalization (Format V4)**: Decoupled IP ranges from repeated metadata. Replaces 28-byte inline records with compact 12-byte ranges (`from`, `to`, `profile_id`) and a dedicated 20-byte Profile Table.
- **Presets & Feature Masks**: Added `--preset` (`full`, `city`, `firewall`, `country`, `threats`) and `--features` bitmask compiler options. Unused metadata fields are masked and adjacent intervals coalesce on the fly, reducing database size down to **5.6 MB** binary (~1.2 MB `.zst`, **233x reduction**) for pure country geo-blocking.
- **Universal Dataset Support**: Dynamic column detection for all IP2Location LITE/Commercial databases (`DB1`, `DB3`, `DB5`, `DB11`) and IP2Proxy (`PX1` - `PX12`).
- **Zstandard Distribution (`.zst`)**: Automated compression using Zstandard level 19, reducing distribution size by **26.8x** (740 MB CSV down to 27.6 MB).
- **Flexible CLI Arguments**: Added `--geo` (or `--db`) and `--proxy` (or `--px`) flags to compiler CLI.

### Changed

- **Rebranding**: Project renamed from `grlg-geo` to `ipatlas`. CLI entry point renamed to `ipatlas`.
- **Binary Header**: Magic updated to `b'ATLS'`.
- **Memory Footprint**: Reduced uncompressed binary size by **55.2%** (from 214.1 MB down to 95.9 MB for unified full global dataset).

## [0.1.0] - 2026-09-29

### Added

- Initial release of zero-copy binary GeoIP and Proxy/VPN threat database compiler and reader.
- Sub-microsecond binary search over memory-mapped intervals (`mmap`).
- 1D streaming interval sweep for disjoint Geolocation (DB5) and Threat Intelligence (PX10) CSVs.
- Bitflag threat classification for hosting, proxies, VPNs, botnets, and residential networks.
