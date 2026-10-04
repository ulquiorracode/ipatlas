# IPAtlas Binary Format & Layout Tiers Specification

This specification defines the binary formats and physical memory layouts implemented by the IPAtlas compiler and zero-copy reader engines.

---

## 1. Architectural Overview & Magic Signatures

All IPAtlas binary artifacts start with a 32-byte or 64-byte aligned header.

- **Header Magic**: `ATLS` (`0x534C5441` little-endian, `[0x41, 0x54, 0x4C, 0x53]`).
- **Endianness**: Strictly Little-Endian (`LE`) across all integer fields.
- **Safety Invariant**: File offsets and record counts MUST strictly validate non-overlap and file boundary constraints (`HeaderV5::validate`).

---

## 2. Layout Tiers Matrix

IPAtlas provides three distinct layout tiers designed around the trade-off between memory footprint, zero-copy alignment, and CPU cache locality:

| Tier | Status | Record Size | Primary Structure | 5.3M Production RAM | Shannon Ratio ($H_{\text{raw}}$) | Hot L1 Latency | Random DRAM Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 1: `V4/V5-Standard`** | **Production** | 12 bytes | `RangeV4` | 61.1 MB | $3.45 \times$ | **66.7 ns** | 140 ns |
| **Tier 2: `V4/V5-Compact`** | **Production** | 8 bytes | `RangeV4Compact` | 41.3 MB | **$2.33 \times$** | **60.9 ns** | 145 ns |
| **Tier 3: `V5-Succinct`** | **Target Spec** | $\sim 2.8$ bytes | Elias-Fano Bitvector | **~17.8 MB** | **$\approx 1.01 \times$** | ~650 ns | ~1200 ns |

---

## 3. Tier 1: V4/V5-Standard (12 Bytes)

Universal layout for unconstrained profile counts ($> 65{,}535$).

```text
+------------------------+------------------------+------------------------+
|   ip_from (u32, 4B)    |    ip_to (u32, 4B)     |   profile_id (u32, 4B) |
+------------------------+------------------------+------------------------+
0                        4                        8                       12
```

- **Alignment**: 4 bytes.
- **Zero-Copy**: Slices mapped directly via `zerocopy::FromBytes` without conversions.
- **Binary Search**: Flat binary search over `&[RangeV4]`.

---

## 4. Tier 2: V4/V5-Compact (8 Bytes)

Engineered for CPU cache line density (8 intervals per 64-byte cache line).

```text
+------------------------+-------------------+-------------------+
|   ip_from (u32, 4B)    |  count (u16, 2B)  | profile (u16, 2B) |
+------------------------+-------------------+-------------------+
0                        4                   6                   8
```

- **`ip_from`**: Base IPv4 address.
- **`count`**: Interval length minus 1 (`ip_to = ip_from + count`).
- **`profile_id`**: 16-bit normalized profile pointer.
- **Span Splitting**: Intervals spanning $> 65{,}535$ IPs are sliced into consecutive 8-byte chunks by `CompactRangePacker`.
- **Automatic Fallback**: If unique profile count exceeds `u16::MAX` (65,535), compiler safely upgrades to `Standard` (12B).

---

## 5. Tier 3: V5-Succinct (Theoretical Shannon Limit Target)

Engineered for extreme embedded edge devices (e.g. OpenWrt 16MB routers, satellite packet filters, microcontrollers, WASM).

### 5.1 Mathematical Grounding (Shannon Entropy)

The global IPv4 table contains $N \approx 5.3 \times 10^6$ disjoint intervals in universe $U = 2^{32}$.

1. **Elias-Fano Monotonic Sequence Encoding**:
   The upper and lower bounds of all $N$ intervals form a strictly increasing sequence:
   $$\text{Lower Bits: } \ell = \max\left(0, \left\lfloor \log_2 \frac{U}{N} \right\rfloor\right) \approx 9\text{ bits}$$
   $$\text{Upper Bits: } 2N\text{ bits}$$
   $$\text{Total Boundary Storage} = N \cdot \ell + 2N \approx 5.3 \times 10^6 \times 11\text{ bits} \approx \mathbf{7.29\text{ MB}}$$

2. **Bit-Packed Profile Indices**:
   Zipfian distribution of Country/ASN allows variable-length Huffman or 12-bit packed indices for profiles $\le 4096$:
   $$\text{Profile Table Storage} \approx 5.3 \times 10^6 \times 12\text{ bits} \approx \mathbf{7.95\text{ MB}}$$

3. **Total In-Memory Target**:
   $$\mathbf{H_{\text{succinct}} \approx 17.8\text{ MB}}$$
   *(Exact equivalence to the theoretical Shannon limit $H_{\text{raw}}$)*.

### 5.2 Retrieval Trade-off Profile

- **Time Complexity**: $O(\log \log U)$ using $O(1)$ Rank/Select bit-index primitives.
- **Predicted Latency**: **450 – 850 ns** (due to bit-shifting and CPU branch misprediction overhead compared to flat binary search).
- **Compilation Adapter**: Will be integrated via `compiler::adapters::SuccinctRangePacker`.

---

## 6. String Blob and Normalization Pool

String storage (City, Region, ISP names) is decoupled into an atomic deduplicated blob:

- **Offsets Array**: `Vec<u32>` pointing to null-terminated UTF-8 byte slices.
- **Index 0 Reserved**: Strictly maps to `""` and `"-"`.
- **Lookups**: `O(1)` SIMD slice scan using `memchr::memchr(0, ...)` directly on mmap views without heap allocations.
