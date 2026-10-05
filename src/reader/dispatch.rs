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
