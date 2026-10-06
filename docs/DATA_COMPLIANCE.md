# Data Compliance & Licensing Guide

This document establishes the official legal and data compliance framework for the **IPAtlas** engine, datasets, and downstream derived artifacts.

---

## 1. Engine vs Data Licensing Separation

A core tenet of the IPAtlas project is the strict boundary between **code** and **data**:

```text
+-------------------------------------------------------+
|                 IPAtlas Engine                        |
|   License: MIT License                                |
|   Scope: Compiler, Reader, Pipeline, CLI, Tests       |
+-------------------------------------------------------+
                           |
                           | processes / queries
                           v
+-------------------------------------------------------+
|                 GeoIP Datasets                        |
|   License: Governed by respective data vendors        |
|   (IP2Location LITE, DB-IP, MaxMind, Commercial feeds)|
+-------------------------------------------------------+
```

1. **The Software (`ipatlas` crate and CLI)**:
   - Released under the permissive **MIT License**.
   - You are free to embed, bundle, distribute, modify, and use IPAtlas in commercial or proprietary closed-source applications without royalty fees.

2. **The Data (`.atlas` binary images)**:
   - Binary database images produced by `ipatlas compile` are **derivative works of the raw input data**.
   - The license of the compiled `.atlas` file is governed by the source data provider's terms of service and license agreement.

---

## 2. Using IP2Location LITE (Free / Open Data)

When compiling from [IP2Location LITE](https://lite.ip2location.com/) CSV databases (e.g., DB1 LITE, DB11 LITE, PX1 LITE, PX11 LITE):

### Terms & Requirements

- **License**: Creative Commons Attribution-ShareAlike 4.0 International ([CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)).
- **Mandatory Attribution**: You **must** provide clear attribution in your application, website, documentation, or about dialog.

### Recommended Attribution Notice

```text
This site or product includes IP2Location LITE data available from https://lite.ip2location.com.
```

### Redistribution Constraints

- If you redistribute or publish raw `.atlas` files compiled from IP2Location LITE data, the resulting dataset remains subject to CC BY-SA 4.0.
- If you build an API service or SaaS product using IPAtlas internally, you do not need to share your proprietary backend code, but you must still provide the attribution notice mentioned above.

---

## 3. Commercial Databases

When utilizing commercial feeds (e.g., IP2Location Commercial DB, MaxMind GeoIP2 / GeoLite2 commercial subscriptions, DB-IP Commercial):

- **License Restrictions**: Most commercial licenses strictly forbid public redistribution of raw data or compiled binary database images.
- **Internal Deployment**: Internal deployment across your organization's servers, edge gateways, Kubernetes clusters, and microservices is typically permitted under single-organization licenses.
- **Proprietary Packaging**: When bundling `.atlas` files inside customer-facing on-premise appliances, verify whether your vendor license grants OEM / redistribution rights.

---

## 4. Privacy & Regulatory Compliance (GDPR, CCPA, ePrivacy)

IPAtlas is architected with modern data protection regulations in mind:

### Zero Personally Identifiable Information (Zero PII)

- IPAtlas databases contain **network intervals and regional/city metadata**, not individual user identifiers.
- It stores **coarse geospatial coordinates** (city/region centroid level) rather than precise GPS coordinates of households.
- **Lossy Quantization (`-O lossy-coords`)**:
  - Rounds latitude and longitude to 2 decimal places (~1.1 km resolution).
  - Explicitly eliminates any potential inference of micro-locations while shrinking database footprint.

### In-Memory Mmap & Sovereign Processing

- **No Remote Telemetry**: IPAtlas performs 100% offline, local memory-mapped lookups. Zero network calls, zero tracking telemetry, and zero third-party dependencies are triggered during lookups.
- **Data Residency**: All lookups occur entirely within your own compute boundary (bare metal, private VPC, or sovereign cloud).

---

## 5. Security & Memory Integrity (`mmap`)

IPAtlas uses memory-mapped files (`memmap2`) for zero-copy lookups. To ensure robust operation in production:

1. **Read-Only Enforced**: Database images are memory-mapped strictly with read-only permissions (`MmapOptions::map()`), preventing memory corruption of underlying disk files.
2. **Bounds & Magic Validation**: Every `.atlas` file begins with a 4-byte magic signature (`IPAT`), format generation check, CRC32 checksum, and strictly verified slice offsets.
3. **No Raw Pointer Crossings**: String offsets and interval tables are strictly validated against buffer boundaries before slice borrowing. Out-of-bounds attempts return safe, descriptive errors (`ReaderError::OutOfBounds`) rather than triggering segmentation faults or panics.
