use crate::models::{Ipv4Range, Ipv4RangeCompact, Ipv6Range, Ipv6RangeSplit64};
use crate::reader::buffer::StorageBuffer;
use crate::reader::guide::GuideTableV4;

/// Pre-validated, branchless dispatch descriptor for IPv4 range tables and columns.
/// Evaluated strictly once during `open()` / `from_mmap()`, eliminating repeated
/// `is_soa()`, `is_compact()`, and `ref_from_bytes` validation on every query.
#[derive(Clone, Copy, Debug)]
pub(crate) enum TableDispatch {
    Empty,
    V4StandardAos {
        offset: usize,
        count: usize,
    },
    V4CompactAos {
        offset: usize,
        count: usize,
    },
    V4StandardSoa {
        ip_from_off: usize,
        ip_to_off: usize,
        prof_off: usize,
        count: usize,
    },
    V4CompactSoa {
        ip_from_off: usize,
        counts_off: usize,
        prof_off: usize,
        count: usize,
    },
    V5StandardAos {
        offset: usize,
        count: usize,
    },
    V5CompactAos {
        offset: usize,
        count: usize,
    },
    V5StandardSoa {
        ip_from_off: usize,
        ip_to_off: usize,
        prof_off: usize,
        count: usize,
    },
    V5CompactSoa {
        ip_from_off: usize,
        counts_off: usize,
        prof_off: usize,
        count: usize,
    },
}

impl TableDispatch {
    /// Executes fast-path raw binary search across any of the 8 layout variants.
    /// Returns `Some((ip_from, ip_to, profile_id))` on match, or `None` on miss.
    #[inline(always)]
    pub fn lookup_raw_v4(
        &self,
        storage: &StorageBuffer,
        guide_v4: &GuideTableV4,
        ip: u32,
    ) -> Option<(u32, u32, usize)> {
        match *self {
            TableDispatch::V4StandardSoa {
                ip_from_off,
                ip_to_off,
                prof_off,
                count,
            }
            | TableDispatch::V5StandardSoa {
                ip_from_off,
                ip_to_off,
                prof_off,
                count,
            } => {
                if count == 0 {
                    return None;
                }
                let (start, end) = guide_v4.guide_bounds(storage, ip, count);
                if start >= end {
                    return None;
                }

                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ip_froms: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(ip_from_off) as *const u32,
                        count,
                    )
                };
                let slice = &ip_froms[start..end];
                let local_idx = crate::reader::branchless::branchless_search_u32(slice, ip)?;
                let idx = start + local_idx;

                let ip_from = ip_froms[idx];
                let tos: &[u32] = unsafe {
                    std::slice::from_raw_parts(storage.as_ptr().add(ip_to_off) as *const u32, count)
                };
                let to = *tos.get(idx)?;
                if ip > to {
                    return None;
                }
                let prof_ids: &[u32] = unsafe {
                    std::slice::from_raw_parts(storage.as_ptr().add(prof_off) as *const u32, count)
                };
                Some((ip_from, to, *prof_ids.get(idx)? as usize))
            }
            TableDispatch::V4CompactSoa {
                ip_from_off,
                counts_off,
                prof_off,
                count,
            }
            | TableDispatch::V5CompactSoa {
                ip_from_off,
                counts_off,
                prof_off,
                count,
            } => {
                if count == 0 {
                    return None;
                }
                let (start, end) = guide_v4.guide_bounds(storage, ip, count);
                if start >= end {
                    return None;
                }

                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ip_froms: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(ip_from_off) as *const u32,
                        count,
                    )
                };
                let slice = &ip_froms[start..end];
                let local_idx = crate::reader::branchless::branchless_search_u32(slice, ip)?;
                let idx = start + local_idx;

                let ip_from = ip_froms[idx];
                let counts: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(counts_off) as *const u16,
                        count,
                    )
                };
                let c = *counts.get(idx)?;
                let to = ip_from.checked_add(c as u32)?;
                if ip > to {
                    return None;
                }
                let prof_ids: &[u16] = unsafe {
                    std::slice::from_raw_parts(storage.as_ptr().add(prof_off) as *const u16, count)
                };
                Some((ip_from, to, *prof_ids.get(idx)? as usize))
            }
            TableDispatch::V4CompactAos { offset, count }
            | TableDispatch::V5CompactAos { offset, count } => {
                if count == 0 {
                    return None;
                }
                let (start, end) = guide_v4.guide_bounds(storage, ip, count);
                if start >= end {
                    return None;
                }

                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[Ipv4RangeCompact] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(offset) as *const Ipv4RangeCompact,
                        count,
                    )
                };
                let slice = &ranges[start..end];
                let local_idx =
                    crate::reader::branchless::branchless_search_by_key_u32(slice, ip, |r| {
                        r.ip_from
                    })?;
                let idx = start + local_idx;

                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                Some((range.ip_from, range.ip_to(), range.profile_id as usize))
            }
            TableDispatch::V4StandardAos { offset, count }
            | TableDispatch::V5StandardAos { offset, count } => {
                if count == 0 {
                    return None;
                }
                let (start, end) = guide_v4.guide_bounds(storage, ip, count);
                if start >= end {
                    return None;
                }

                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[Ipv4Range] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(offset) as *const Ipv4Range,
                        count,
                    )
                };
                let slice = &ranges[start..end];
                let local_idx =
                    crate::reader::branchless::branchless_search_by_key_u32(slice, ip, |r| {
                        r.ip_from
                    })?;
                let idx = start + local_idx;

                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                Some((range.ip_from, range.ip_to, range.profile_id as usize))
            }
            TableDispatch::Empty => None,
        }
    }
}

/// Pre-validated, branchless dispatch descriptor for IPv6 range tables.
#[derive(Clone, Copy, Debug)]
pub(crate) enum TableDispatchV6 {
    Empty,
    StandardAos { offset: usize, count: usize },
    Split64Compact { offset: usize, count: usize },
}

impl TableDispatchV6 {
    /// Executes fast-path raw binary search across IPv6 layout variants.
    #[inline(always)]
    pub fn lookup_raw_v6(&self, storage: &StorageBuffer, ip: u128) -> Option<(u128, u128, usize)> {
        match *self {
            TableDispatchV6::Split64Compact { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[Ipv6RangeSplit64] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(offset) as *const Ipv6RangeSplit64,
                        count,
                    )
                };
                let ip_hi = (ip >> 64) as u64;
                let idx =
                    crate::reader::branchless::branchless_search_by_key_u64(ranges, ip_hi, |r| {
                        r.ip_from_hi
                    })?;
                let range = ranges.get(idx)?;
                if !range.contains_hi(ip_hi) {
                    return None;
                }
                let from = (range.ip_from_hi as u128) << 64;
                let to = ((range.ip_to_hi() as u128) << 64) | 0xFFFF_FFFF_FFFF_FFFF;
                Some((from, to, range.profile_id as usize))
            }
            TableDispatchV6::StandardAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[Ipv6Range] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(offset) as *const Ipv6Range,
                        count,
                    )
                };
                let idx =
                    crate::reader::branchless::branchless_search_by_key_u128(ranges, ip, |r| {
                        r.ip_from()
                    })?;
                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                Some((range.ip_from(), range.ip_to(), range.profile_id() as usize))
            }
            TableDispatchV6::Empty => None,
        }
    }
}
