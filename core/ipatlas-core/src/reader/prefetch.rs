//! Cross-platform hardware prefetching hints and memory intrinsics.
//!
//! Provides zero-cost CPU prefetching hints for x86_64 and AArch64 with seamless
//! no-op fallback on other architectures (WASM, RISC-V, etc.).

/// Issues an asynchronous memory prefetch hint to bring data into the L1/L2 cache.
///
/// On x86_64, translates to `prefetcht0`.
/// On aarch64, translates to `prfm pldl1keep`.
/// On other platforms, compiles away to a 0-cost no-op.
///
/// Hardware prefetch instructions never fault, trap, or generate segmentation violations
/// even if given an invalid, null, or out-of-bounds pointer.
#[inline(always)]
pub fn prefetch_read_l1<T>(ptr: *const T) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::x86_64::_mm_prefetch(ptr as *const i8, core::arch::x86_64::_MM_HINT_T0);
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        #[cfg(target_arch = "aarch64")]
        core::arch::aarch64::__prefetch(
            ptr as *const u8,
            core::arch::aarch64::_PREFETCH_READ,
            core::arch::aarch64::_PREFETCH_LOCALITY3,
        );
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = ptr;
    }
}
