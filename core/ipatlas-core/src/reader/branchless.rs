//! Branchless, division-free binary search primitives with explicit prefetch hints.
//!
//! Provides `cmov`-friendly branchless binary search algorithms for contiguous slices.
//! Unlike standard library `slice::binary_search`, branchless binary search maintains a power-of-two
//! or halved search stride that avoids data-dependent branch mispredictions (saving ~15-20 cycles per miss)
//! and eliminates all integer divisions.

/// Performs a branchless binary search over a slice of monotonically increasing `u32` keys.
///
/// Returns the index of the greatest element less than or equal to `target`.
/// If all elements are greater than `target`, returns `None`.
#[inline(always)]
pub fn branchless_search_u32(slice: &[u32], target: u32) -> Option<usize> {
    let mut len = slice.len();
    if len == 0 {
        return None;
    }

    let mut base = 0;
    while len > 1 {
        let half = len >> 1;
        let mid = base + half;
        // Inlined hardware prefetch for cacheline anticipation
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if half >= 8 {
            let next_quarter = base + (half >> 1);
            unsafe {
                crate::reader::prefetch_read_l1(slice.as_ptr().add(next_quarter));
            }
        }

        // Branchless condition: compiled to `cmov` / conditional select
        let cmp = slice[mid] <= target;
        base = if cmp { mid } else { base };
        len -= half;
    }

    if slice[base] <= target {
        Some(base)
    } else {
        None
    }
}

/// Performs a branchless binary search over a slice of items using an extractor closure.
///
/// Extracts a `u32` comparison key from each element and finds the greatest element `<= target`.
#[inline(always)]
pub fn branchless_search_by_key_u32<T, F>(slice: &[T], target: u32, mut key_fn: F) -> Option<usize>
where
    F: FnMut(&T) -> u32,
{
    let mut len = slice.len();
    if len == 0 {
        return None;
    }

    let mut base = 0;
    while len > 1 {
        let half = len >> 1;
        let mid = base + half;

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if half >= 8 {
            let next_quarter = base + (half >> 1);
            unsafe {
                crate::reader::prefetch_read_l1(slice.as_ptr().add(next_quarter));
            }
        }

        let cmp = key_fn(&slice[mid]) <= target;
        base = if cmp { mid } else { base };
        len -= half;
    }

    if key_fn(&slice[base]) <= target {
        Some(base)
    } else {
        None
    }
}

/// Performs a branchless binary search over a slice of items using a `u64` extractor closure.
#[inline(always)]
pub fn branchless_search_by_key_u64<T, F>(slice: &[T], target: u64, mut key_fn: F) -> Option<usize>
where
    F: FnMut(&T) -> u64,
{
    let mut len = slice.len();
    if len == 0 {
        return None;
    }

    let mut base = 0;
    while len > 1 {
        let half = len >> 1;
        let mid = base + half;

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if half >= 8 {
            let next_quarter = base + (half >> 1);
            unsafe {
                crate::reader::prefetch_read_l1(slice.as_ptr().add(next_quarter));
            }
        }

        let cmp = key_fn(&slice[mid]) <= target;
        base = if cmp { mid } else { base };
        len -= half;
    }

    if key_fn(&slice[base]) <= target {
        Some(base)
    } else {
        None
    }
}

/// Performs a branchless binary search over a slice of items using a `u128` extractor closure.
#[inline(always)]
pub fn branchless_search_by_key_u128<T, F>(
    slice: &[T],
    target: u128,
    mut key_fn: F,
) -> Option<usize>
where
    F: FnMut(&T) -> u128,
{
    let mut len = slice.len();
    if len == 0 {
        return None;
    }

    let mut base = 0;
    while len > 1 {
        let half = len >> 1;
        let mid = base + half;

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if half >= 8 {
            let next_quarter = base + (half >> 1);
            unsafe {
                crate::reader::prefetch_read_l1(slice.as_ptr().add(next_quarter));
            }
        }

        let cmp = key_fn(&slice[mid]) <= target;
        base = if cmp { mid } else { base };
        len -= half;
    }

    if key_fn(&slice[base]) <= target {
        Some(base)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branchless_search_u32_basic() {
        let values = [10, 20, 30, 40, 50, 60, 70];
        assert_eq!(branchless_search_u32(&values, 5), None);
        assert_eq!(branchless_search_u32(&values, 10), Some(0));
        assert_eq!(branchless_search_u32(&values, 15), Some(0));
        assert_eq!(branchless_search_u32(&values, 20), Some(1));
        assert_eq!(branchless_search_u32(&values, 45), Some(3));
        assert_eq!(branchless_search_u32(&values, 70), Some(6));
        assert_eq!(branchless_search_u32(&values, 100), Some(6));
    }

    #[test]
    fn test_branchless_search_single_and_empty() {
        let empty: [u32; 0] = [];
        assert_eq!(branchless_search_u32(&empty, 10), None);

        let single = [42];
        assert_eq!(branchless_search_u32(&single, 10), None);
        assert_eq!(branchless_search_u32(&single, 42), Some(0));
        assert_eq!(branchless_search_u32(&single, 100), Some(0));
    }
}
