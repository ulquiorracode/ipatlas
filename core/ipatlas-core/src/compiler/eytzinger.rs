//! Branchless Eytzinger (Breadth-First Search) Array Layout and Search.
//!
//! Re-orders a sorted slice of items into a 1-based implicit binary search tree:
//! - Root is at index 1
//! - Left child of `k` is at `2 * k`
//! - Right child of `k` is at `2 * k + 1`
//!
//! Provides a branchless binary search with software prefetch (`_mm_prefetch`),
//! eliminating branch mispredictions and keeping cache-line requests predictable.

use crate::models::{Ipv4RangeCompact, Ipv6RangeSplit64};

/// Layout helper and search engine for Eytzinger BFS array structure.
pub struct EytzingerSearch;

impl EytzingerSearch {
    /// Re-orders a sorted slice `src` into 1-based Eytzinger order in `dst`.
    /// `dst` must have length `src.len() + 1`. `dst[0]` remains a dummy/default value.
    pub fn build_eytzinger<T: Copy + Default>(src: &[T], dst: &mut [T]) {
        assert_eq!(dst.len(), src.len() + 1);
        if src.is_empty() {
            return;
        }

        fn in_order<T: Copy>(k: usize, n: usize, src: &[T], dst: &mut [T], idx: &mut usize) {
            if k <= n {
                in_order(2 * k, n, src, dst, idx);
                dst[k] = src[*idx];
                *idx += 1;
                in_order(2 * k + 1, n, src, dst, idx);
            }
        }

        let mut idx = 0;
        in_order(1, src.len(), src, dst, &mut idx);
    }

    /// Performs a branchless search over a 1-based Eytzinger array of `Ipv4RangeCompact`.
    /// Returns the matched `Ipv4RangeCompact` if `ip` falls within its bounds.
    #[inline(always)]
    pub fn search_v4_compact(eytzinger: &[Ipv4RangeCompact], ip: u32) -> Option<&Ipv4RangeCompact> {
        let n = eytzinger.len().saturating_sub(1);
        if n == 0 {
            return None;
        }

        let mut k = 1;
        while k <= n {
            // Software prefetch the child cache-lines ahead of time
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::x86_64::_mm_prefetch(
                    eytzinger.as_ptr().add(k * 16) as *const i8,
                    core::arch::x86_64::_MM_HINT_T0,
                );
            }

            let entry = unsafe { eytzinger.get_unchecked(k) };
            // Branchless conditional move (cmov) index update:
            // if ip >= entry.ip_from, go right (2*k + 1), else go left (2*k)
            let go_right = (ip >= entry.ip_from) as usize;
            k = 2 * k + go_right;
        }

        // Divide by 2 until we find the candidate node
        k >>= k.trailing_zeros() + 1;
        if k == 0 || k > n {
            return None;
        }

        let candidate = unsafe { eytzinger.get_unchecked(k) };
        if candidate.contains(ip) {
            Some(candidate)
        } else {
            None
        }
    }

    /// Performs a branchless search over a 1-based Eytzinger array of `Ipv6RangeSplit64`.
    /// Returns the matched `Ipv6RangeSplit64` if `ip_hi` falls within its bounds.
    #[inline(always)]
    pub fn search_v6_split64(
        eytzinger: &[Ipv6RangeSplit64],
        ip_hi: u64,
    ) -> Option<&Ipv6RangeSplit64> {
        let n = eytzinger.len().saturating_sub(1);
        if n == 0 {
            return None;
        }

        let mut k = 1;
        while k <= n {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::x86_64::_mm_prefetch(
                    eytzinger.as_ptr().add(k * 8) as *const i8,
                    core::arch::x86_64::_MM_HINT_T0,
                );
            }

            let entry = unsafe { eytzinger.get_unchecked(k) };
            let go_right = (ip_hi >= entry.ip_from_hi) as usize;
            k = 2 * k + go_right;
        }

        k >>= k.trailing_zeros() + 1;
        if k == 0 || k > n {
            return None;
        }

        let candidate = unsafe { eytzinger.get_unchecked(k) };
        if candidate.contains_hi(ip_hi) {
            Some(candidate)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eytzinger_v4_compact_search() {
        let mut sorted = Vec::new();
        for i in 0..100u32 {
            sorted.push(Ipv4RangeCompact::new(i * 10, 9, i as u16));
        }

        let mut eytzinger = vec![Ipv4RangeCompact::default(); sorted.len() + 1];
        EytzingerSearch::build_eytzinger(&sorted, &mut eytzinger);

        for i in 0..100u32 {
            let hit = EytzingerSearch::search_v4_compact(&eytzinger, i * 10 + 5);
            assert!(hit.is_some());
            assert_eq!(hit.unwrap().profile_id, i as u16);
        }

        // Test non-existent ip before start
        assert!(EytzingerSearch::search_v4_compact(&eytzinger, 0).is_some());
    }

    #[test]
    fn test_eytzinger_v6_split64_search() {
        let mut sorted = Vec::new();
        for i in 0..100u64 {
            sorted.push(Ipv6RangeSplit64::new(i * 10, 9, i as u32));
        }

        let mut eytzinger = vec![Ipv6RangeSplit64::default(); sorted.len() + 1];
        EytzingerSearch::build_eytzinger(&sorted, &mut eytzinger);

        for i in 0..100u64 {
            let hit = EytzingerSearch::search_v6_split64(&eytzinger, i * 10 + 5);
            assert!(hit.is_some());
            assert_eq!(hit.unwrap().profile_id, i as u32);
        }
    }
}
