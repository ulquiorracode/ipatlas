<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-01

### Added

- **Profile ID Normalization (Format V4)**: Decoupled IP ranges from repeated metadata. Replaces 28-byte inline records with compact 12-byte ranges (`from`, `to`, `profile_id`) and a dedicated 20-byte Profile Table.
- **Presets & Feature Masks**: Added `--preset` (`full`, `city`, `firewall`, `country`, `threats`) and `--features` bitmask compiler options. Unused metadata fields are masked and adjacent intervals coalesce on the fly, reducing database size down to **5.6 MB** binary (~1.2 MB `.zst`, **233x reduction**) for pure country geo-blocking.
- **Universal Dataset Support**: Dynamic column detection for all IP2Location LITE/Commercial databases (`DB1`, `DB3`, `DB5`, `DB11`) and IP2Proxy (`PX1` - `PX12`).
- **Zstandard Distribution (`.zst`)**: Automated compression using Zstandard level 19, reducing distribution size by **26.8x** (740 MB CSV down to 27.6 MB).
- **Flexible CLI Arguments**: Added `--geo` (or `--db`) and `--proxy` (or `--px`) flags to compiler CLI.

### Changed

- **Rebranding**: Project renamed from `grlg-geo` to `ipatlas`. CLI entry point renamed to `ipatlas`.
- **Binary Header**: Magic updated to `b'ATLS'` (with backward compatibility for `b'GRLG'`).
- **Memory Footprint**: Reduced uncompressed binary size by **55.2%** (from 214.1 MB down to 95.9 MB for unified full global dataset).

### Deprecated / Compatibility

- `GrlgReader` alias preserved in Python SDK for backward compatibility with `IpAtlasReader`.
- Legacy CLI flags (`--db5`, `--px10`) retained as aliases.

## [0.1.0] - 2026-09-29

### Added

- Initial release of zero-copy binary GeoIP and Proxy/VPN threat database compiler and reader.
- Sub-microsecond binary search over memory-mapped intervals (`mmap`).
- 1D streaming interval sweep for disjoint Geolocation (DB5) and Threat Intelligence (PX10) CSVs.
- Bitflag threat classification for hosting, proxies, VPNs, botnets, and residential networks.
