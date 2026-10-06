//! Composable Stream and Topology Adapters for Compiler Optimization Pipeline.
//!
//! Inspired by StateFS/Stitch-rs decoupled architecture:
//! - Separation of Concerns: Sweep line only performs geometric intersection of disjoint streams.
//! - Adapters perform targeted transformations (quantization, coalescing, layout packing).
//! - Zero runtime cost: Monomorphic iterator adapters inlined by LLVM.

use crate::compiler::sweep::{MergedEntry, MergedEntryV6};
use crate::models::{quantize_coordinate, FeatureMask, Ipv4RangeCompact};

// ============================================================================
// FeatureMask & Coordinate Quantization Adapters
// ============================================================================

/// Trait implemented by merged entries that support feature masking and quantization.
pub trait TransformableEntry: Sized {
    fn apply_feature_mask(&mut self, mask: FeatureMask);
    fn apply_lossy_coords(&mut self);
}

impl TransformableEntry for MergedEntry {
    #[inline]
    fn apply_feature_mask(&mut self, mask: FeatureMask) {
        if !mask.has_country() {
            self.country = *b"--";
        }
        if !mask.has_region() {
            self.reg_idx = 0;
        }
        if !mask.has_city() {
            self.city_idx = 0;
        }
        if !mask.has_isp() {
            self.isp_idx = 0;
        }
        if !mask.has_asn() {
            self.asn = 0;
        }
        if !mask.has_threats() {
            self.flags = 0;
        }
        if !mask.has_coords() {
            self.lat_fixed = 0;
            self.lon_fixed = 0;
        }
    }

    #[inline]
    fn apply_lossy_coords(&mut self) {
        self.lat_fixed = quantize_coordinate(self.lat_fixed);
        self.lon_fixed = quantize_coordinate(self.lon_fixed);
    }
}

impl TransformableEntry for MergedEntryV6 {
    #[inline]
    fn apply_feature_mask(&mut self, mask: FeatureMask) {
        if !mask.has_country() {
            self.country = *b"--";
        }
        if !mask.has_region() {
            self.reg_idx = 0;
        }
        if !mask.has_city() {
            self.city_idx = 0;
        }
        if !mask.has_isp() {
            self.isp_idx = 0;
        }
        if !mask.has_asn() {
            self.asn = 0;
        }
        if !mask.has_threats() {
            self.flags = 0;
        }
        if !mask.has_coords() {
            self.lat_fixed = 0;
            self.lon_fixed = 0;
        }
    }

    #[inline]
    fn apply_lossy_coords(&mut self) {
        self.lat_fixed = quantize_coordinate(self.lat_fixed);
        self.lon_fixed = quantize_coordinate(self.lon_fixed);
    }
}

/// Iterator adapter applying symmetric lossy coordinate quantization.
pub struct LossyCoordsAdapter<I> {
    inner: I,
}

impl<I> LossyCoordsAdapter<I> {
    #[inline]
    pub fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I> Iterator for LossyCoordsAdapter<I>
where
    I: Iterator,
    I::Item: TransformableEntry,
{
    type Item = I::Item;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|mut item| {
            item.apply_lossy_coords();
            item
        })
    }
}

// ============================================================================
// Interval Coalescing Topology Adapters
// ============================================================================

/// Trait for entries that can be tested for adjacency and attribute equality.
pub trait CoalescibleEntry: Copy {
    type Key: PartialOrd + Copy;

    fn key_from(&self) -> Self::Key;
    fn key_to(&self) -> Self::Key;
    fn set_key_to(&mut self, to: Self::Key);
    fn can_merge_with(&self, other: &Self) -> bool;
}

impl CoalescibleEntry for MergedEntry {
    type Key = u32;

    #[inline]
    fn key_from(&self) -> u32 {
        self.ip_from
    }

    #[inline]
    fn key_to(&self) -> u32 {
        self.ip_to
    }

    #[inline]
    fn set_key_to(&mut self, to: u32) {
        self.ip_to = to;
    }

    #[inline]
    fn can_merge_with(&self, other: &Self) -> bool {
        self.ip_to < u32::MAX && self.ip_to + 1 == other.ip_from && self.matches_attributes(other)
    }
}

impl CoalescibleEntry for MergedEntryV6 {
    type Key = u128;

    #[inline]
    fn key_from(&self) -> u128 {
        self.ip_from
    }

    #[inline]
    fn key_to(&self) -> u128 {
        self.ip_to
    }

    #[inline]
    fn set_key_to(&mut self, to: u128) {
        self.ip_to = to;
    }

    #[inline]
    fn can_merge_with(&self, other: &Self) -> bool {
        self.ip_to < u128::MAX && self.ip_to + 1 == other.ip_from && self.matches_attributes(other)
    }
}

/// Topology adapter that coalesces contiguous adjacent intervals with identical attributes.
pub struct CoalesceAdapter<I, E>
where
    E: CoalescibleEntry,
    I: Iterator<Item = E>,
{
    inner: I,
    pending_prev: Option<E>,
    finished: bool,
}

impl<I, E> CoalesceAdapter<I, E>
where
    E: CoalescibleEntry,
    I: Iterator<Item = E>,
{
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            pending_prev: None,
            finished: false,
        }
    }
}

impl<I, E> Iterator for CoalesceAdapter<I, E>
where
    E: CoalescibleEntry,
    I: Iterator<Item = E>,
{
    type Item = E;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        loop {
            let next_raw = self.inner.next();

            match (self.pending_prev.take(), next_raw) {
                (None, None) => {
                    self.finished = true;
                    return None;
                }
                (None, Some(curr)) => {
                    self.pending_prev = Some(curr);
                }
                (Some(prev), None) => {
                    self.finished = true;
                    return Some(prev);
                }
                (Some(mut prev), Some(curr)) => {
                    if prev.can_merge_with(&curr) {
                        prev.set_key_to(curr.key_to());
                        self.pending_prev = Some(prev);
                    } else {
                        self.pending_prev = Some(curr);
                        return Some(prev);
                    }
                }
            }
        }
    }
}

// ============================================================================
// Layout Storage Adapters
// ============================================================================

/// Emits compact 8-byte V4 ranges, splitting spans > u16::MAX into chunks.
pub struct CompactRangePacker;

impl CompactRangePacker {
    #[inline]
    pub fn pack_span(ip_from: u32, ip_to: u32, profile_id: u16, sink: &mut Vec<Ipv4RangeCompact>) {
        let mut curr_from = ip_from;
        while curr_from <= ip_to {
            let span = (ip_to - curr_from).min(u16::MAX as u32);
            sink.push(Ipv4RangeCompact::new(curr_from, span as u16, profile_id));
            if span == u16::MAX as u32 && curr_from < u32::MAX - span {
                curr_from += span + 1;
            } else {
                break;
            }
        }
    }
}

/// Emits compact 16-byte IPv6 Split-64 ranges (`Ipv6RangeSplit64`).
///
/// ### Over-Approximation Contract (Lossy Opt-In)
/// Truncates the lower 64 bits (`ip >> 64`), mapping all IPv6 addresses within a `/64` prefix
/// to the same high 64-bit integer.
/// - **Sub-`/64` Intervals**: Any sub-`/64` span (e.g. `[2001:db8::1, 2001:db8::ffff]`) is
///   over-approximated to cover the entire `/64` block (`2001:db8::0/64`).
/// - **Enforced Preconditions**: This format must only be used with explicit user opt-in
///   (`OptimizationConfig::split64_v6 = true` or CLI `--split64-v6` / `-O split64-v6`).
///   When intervals are already `/64`-aligned (e.g. standard BGP / RIR allocations),
///   representation is exact. For sub-`/64` firewall or threat ranges, addresses outside
///   the exact sub-range will match (over-approximation).
pub struct Split64RangePacker;

impl Split64RangePacker {
    #[inline]
    pub fn pack_span(
        ip_from: u128,
        ip_to: u128,
        profile_id: u32,
        sink: &mut Vec<crate::models::Ipv6RangeSplit64>,
    ) {
        let from_hi = (ip_from >> 64) as u64;
        let to_hi = (ip_to >> 64) as u64;

        let mut curr_from_hi = from_hi;
        while curr_from_hi <= to_hi {
            let span_hi = (to_hi - curr_from_hi).min(u32::MAX as u64);
            sink.push(crate::models::Ipv6RangeSplit64::new(
                curr_from_hi,
                span_hi as u32,
                profile_id,
            ));
            if span_hi == u32::MAX as u64 && curr_from_hi < u64::MAX - span_hi {
                curr_from_hi += span_hi + 1;
            } else {
                break;
            }
        }
    }
}

/// Pipeline extension trait enabling fluent `.coalesce()` and `.quantize_coords()` composition.
pub trait CompilerStreamExt: Iterator + Sized {
    /// Appends lossy coordinate quantization adapter.
    fn quantize_coords(self) -> LossyCoordsAdapter<Self>
    where
        Self::Item: TransformableEntry,
    {
        LossyCoordsAdapter::new(self)
    }

    /// Appends adjacent interval coalescing adapter.
    fn coalesce(self) -> CoalesceAdapter<Self, Self::Item>
    where
        Self::Item: CoalescibleEntry,
    {
        CoalesceAdapter::new(self)
    }
}

impl<T: Iterator> CompilerStreamExt for T {}
