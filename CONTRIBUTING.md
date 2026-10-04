# Contributing to IPAtlas

Thank you for your interest in contributing to **IPAtlas**! We welcome contributions of all kinds: performance optimizations, bug fixes, architecture improvements, documentation, and dataset adapters.

Please take a moment to review these guidelines before submitting code.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Branching Strategy](#branching-strategy)
- [Conventional Commits](#conventional-commits)
- [Development Setup](#development-setup)
- [Coding Standards & Core Invariants](#coding-standards--core-invariants)
- [Pull Request Workflow](#pull-request-workflow)

---

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## Branching Strategy

Our repository uses a GitFlow-inspired branching model:

- **`main`**: Production/stable releases only. Protected branch; direct commits are prohibited.
- **`dev`**: Active development integration branch. Protected branch; all feature and fix PRs must target `dev`.
- **`feature/<name>`**: New features and enhancements, branched from `dev` and merged back into `dev` via PR.
- **`fix/<name>`** or **`hotfix/<name>`**: Bug fixes, branched from `dev` (or `main` for critical production hotfixes).

```text
main   ───────────────────────────● (v0.7.0)
                                 /
dev    ──────●──────────●───────●─── (Active Development)
              \        /
feature/v5     ●──────●             (Feature Branch)
```

---

## Conventional Commits

We strictly follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification. All commit messages must be formatted as:

```text
<type>(<optional-scope>): <description in imperative mood>

[optional body]

[optional footer(s)]
```

### Allowed Types

| Type | Description | Example |
| :--- | :--- | :--- |
| `feat` | A new feature or capability | `feat(reader): add lazy decompression iterator for profiles` |
| `fix` | A bug fix | `fix(sweep): handle adjacent interval boundaries on overflow` |
| `docs` | Documentation changes only | `docs(readme): update hardware efficiency matrix` |
| `refactor` | Code restructuring without changing behavior | `refactor(pipeline): extract u-cycle stage contracts` |
| `perf` | A code change that improves performance | `perf(lookup): align hot cache binary search loop` |
| `test` | Adding missing tests or correcting existing tests | `test(succinct): add roundtrip verification for elias-fano` |
| `build` | Changes affecting build system or dependencies | `build(cargo): pin stitch-rs revision` |
| `ci` | Changes to CI workflows and automation | `ci(github): add matrix for ubuntu, windows, and macos` |
| `chore` | Routine maintenance or tooling chores | `chore: format codebase with cargo fmt` |

---

## Development Setup

### 1. Prerequisites

Ensure you have installed:

1. **Rust 1.74+** (MSRV 1.74, see `rust-version` in `Cargo.toml`).
2. **Cargo tools** (optional, recommended):
   ```bash
   cargo install cargo-deny cargo-audit
   ```

### 2. Build & Test

```bash
# Clone the repository
git clone https://github.com/ulquiorracode/ipatlas.git
cd ipatlas

# Run all test suites
cargo test --all-targets

# Run tests without default features (minimal reader verification)
cargo test --no-default-features

# Smoke test benchmark harnesses
cargo test --benches
```

---

## Coding Standards & Core Invariants

### 1. Reader Hot Path Invariants

- **Zero Allocations**: The reader query hot path (`lookup_ref`, `query_pipeline`) must perform zero heap allocations.
- **No Direct Panics**: Never crash or panic in library code. Return typed `Result` or `Option`.
- **No `eprintln!` in Library Code**: Library crates must return errors or warnings (`warnings: Vec<String>`); console output belongs exclusively in `src/main.rs`.
- **Minimal Dependencies**: The reader-only build (`--no-default-features`) must strictly depend only on lightweight foundational crates (`memmap2`, `zerocopy`, `memchr`, `thiserror`, `stitch-rs`). Heavy dependencies (`rayon`, `clap`, `anyhow`, `zstd`) must remain optional behind feature flags.

### 2. Safety & Invariants

- Every `unsafe` block must be preceded by a clear `// SAFETY: <rationale>` comment explaining why memory safety invariants are upheld.
- All binary layout structs must derive `zerocopy` traits (`FromBytes`, `IntoBytes`, `Immutable`, `KnownLayout`) with verified `#[repr(C)]` or `#[repr(C, packed)]` layout.

### 3. Binary Format Changes

Any binary specification or header layout change requires:
1. Updating [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md).
2. Updating [`CHANGELOG.md`](CHANGELOG.md).
3. Providing backward-compatibility validation or migration documentation in `docs/`.

### 4. Benchmark Reproducibility

Performance claims must include exact reproduction parameters:
- Hardware testbed (CPU model, clock frequency, OS).
- Dataset hash and record count.
- Benchmark command and harness (`cargo bench --bench lookup_bench`).
- Hot-L1 vs cold/random-miss figures reported separately.

---

## Pull Request Workflow

1. Create a branch from `dev`:
   ```bash
   git checkout dev
   git pull origin dev
   git checkout -b feat/my-optimization
   ```
2. Make your edits following English code artifact standards.
3. Verify local quality gates:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-targets
   cargo check --no-default-features
   cargo doc --no-deps --all-features
   ```
4. Push and submit a Pull Request targeting `dev` using the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
