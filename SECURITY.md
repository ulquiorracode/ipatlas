# Security Policy

The **IPAtlas** team takes the stability, memory safety, and security of threat intelligence and networking engines seriously. We appreciate the responsible disclosure of any vulnerabilities discovered in the project.

## Supported Versions

Only the latest active development and release versions receive security updates:

| Version | Supported |
| :--- | :---: |
| `0.7.x` (`main` / `dev`) | :white_check_mark: |
| `< 0.7.0` | :x: |

---

## Reporting a Vulnerability

> [!IMPORTANT]
> **Please do not report security vulnerabilities through public GitHub issues, pull requests, or public discussions.**

If you discover a security vulnerability in IPAtlas, please report it privately:

1. **GitHub Security Advisory (Preferred):**
   - Navigate to the [Security Advisories](https://github.com/ulquiorracode/ipatlas/security/advisories) tab of this repository.
   - Click **"Report a vulnerability"** to open a confidential report directly with the maintainers.

2. **Direct Maintainer Contact:**
   - Report directly to the project lead at [@ulquiorracode](https://github.com/ulquiorracode).

### What to Include in Your Report

To help us triage and resolve the issue quickly, please provide:

- A clear description of the vulnerability and its potential impact.
- Affected component(s) (e.g., Reader Engine, mmap bounds verification, Embedded Zstd decompression).
- A minimal proof-of-concept database file (`.bin`) or code snippet triggering the issue.
- Target platform and Rust toolchain version.

---

## Scope of Security Concerns

We are particularly interested in reports concerning:

- **Out-of-Bounds Memory Access**: Flaws allowing crafted database binary files to read outside memory-mapped boundaries.
- **Decompression Bombs (DoS)**: Unbounded memory allocation during embedded Zstd or stream decompression.
- **Header Parsing Exploits**: Integer overflows or corrupted offsets in section header parsing causing undefined behavior or crashes.
- **Zero-Copy Invariant Violations**: Unaligned memory reads or type casting violations bypassing `zerocopy` guarantees.

---

## Response Process

- **Acknowledgement**: We aim to acknowledge receipt of your vulnerability report within **48 hours**.
- **Assessment**: We will validate the issue, determine its severity, and keep you informed of our progress.
- **Remediation & Disclosure**: Once a fix is verified, a patched release will be published alongside a coordinated security advisory crediting your discovery (unless you request anonymity).
