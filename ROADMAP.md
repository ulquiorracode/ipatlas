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

## v0.8.0 — Dual-Stack IPv6 & WebAssembly Engine 📝 Planned

**Goal:** Deliver full dual-stack IPv4/IPv6 querying, a lightweight WASM compilation target for edge proxies (Cloudflare Workers, Fastly Compute, Envoy), and direct C-ABI exports.

- [ ] **Dual-Stack IPv6 Support**:
  - Support full 128-bit IPv6 interval sweep and binary search (`RangeV6` 36 bytes).
  - Dual-tree header layout with separate IPv4 and IPv6 section offsets.
- [ ] **WebAssembly (WASM) Reader Target**:
  - Compile minimal reader to `wasm32-unknown-unknown` and `wasm32-wasip1`.
  - Zero-heap allocation lookup inside browser/edge sandbox.
- [ ] **C-ABI Shared Library (`libipatlas.so` / `ipatlas.dll`)**:
  - Expose safe C-compatible exports (`ipatlas_open`, `ipatlas_lookup_ipv4`, `ipatlas_close`).
  - Provide C/C++ header `ipatlas.h` for integration into nginx, HAProxy, and game servers.

---

## v0.9.0 — Real-Time Memory Map Hot-Reload & Dynamic Feeds 📝 Planned

**Goal:** Support continuous in-flight database updates without server restarts, lock contention, or connection drops.

- [ ] **Atomic `mmap` Pointer Swapping**:
  - Thread-safe `ArcSwap` / generational pointer wrapper allowing background reloading of `.bin` files while lookups proceed concurrently.
- [ ] **Delta Feed Ingestion**:
  - Incremental update stream format applying IP reputation additions and revocations directly in memory.

---

## v1.0.0 — Production LTS Release 📝 Planned

**Goal:** Establish formal binary container stability (SemVer 1.0 guarantee), finalized C and Rust APIs, and comprehensive ecosystem benchmarks.

- [ ] Frozen binary specification with forward and backward compatibility guarantees.
- [ ] High-volume integration test suite against 100M+ real-world query traces.
- [ ] Official documentation portal and precompiled binary releases across Linux, Windows, and macOS.
