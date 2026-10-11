//! AOT Distribution Footer format and constants for IPAtlas containers.
//!
//! Provides a trailing metadata footer located at the end of the container file.
//! The footer is identified by a 4-byte magic `ATFT` ("Atlas Footer") at the very end of the file.
//! If present, it enables instant zero-cost memory mapping of the 65,536-entry Stage 1 Guide Table
//! and optional Bogon/unallocated negative-cache presence bitset.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// 4-byte footer magic tag placed at the last 4 bytes of the container.
pub const FOOTER_MAGIC: [u8; 4] = *b"ATFT";

/// Fixed size of the trailing footer index record (32 bytes).
pub const FOOTER_INDEX_SIZE: usize = 32;

/// Footer capability flags bitmask.
pub const FOOTER_FLAG_GUIDE_V4: u32 = 1 << 0;
pub const FOOTER_FLAG_BOGON_RLE: u32 = 1 << 1;

/// Fixed-size trailing descriptor (32 bytes) located at `file_len - 32..file_len`.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ContainerFooter {
    pub guide_offset: u64,
    pub guide_len: u32,
    pub bogon_offset: u64,
    pub bogon_len: u32,
    pub flags: u32,
    pub magic: [u8; 4],
}

impl ContainerFooter {
    #[inline(always)]
    pub fn new(
        guide_offset: u64,
        guide_len: u32,
        bogon_offset: u64,
        bogon_len: u32,
        flags: u32,
    ) -> Self {
        Self {
            guide_offset,
            guide_len,
            bogon_offset,
            bogon_len,
            flags,
            magic: FOOTER_MAGIC,
        }
    }

    #[inline(always)]
    pub fn guide_offset(&self) -> u64 {
        self.guide_offset
    }

    #[inline(always)]
    pub fn guide_len(&self) -> u32 {
        self.guide_len
    }

    #[inline(always)]
    pub fn bogon_offset(&self) -> u64 {
        self.bogon_offset
    }

    #[inline(always)]
    pub fn bogon_len(&self) -> u32 {
        self.bogon_len
    }

    #[inline(always)]
    pub fn flags(&self) -> u32 {
        self.flags
    }

    #[inline(always)]
    pub fn has_guide_v4(&self) -> bool {
        (self.flags & FOOTER_FLAG_GUIDE_V4) != 0 && self.guide_len == 524288
    }

    #[inline(always)]
    pub fn has_bogon_rle(&self) -> bool {
        (self.flags & FOOTER_FLAG_BOGON_RLE) != 0 && self.bogon_len > 0
    }

    /// Validates footer offsets against file boundaries and payload bounds.
    pub fn validate(&self, file_len: u64, min_payload_end: u64) -> Result<(), &'static str> {
        if self.magic != FOOTER_MAGIC {
            return Err("Invalid footer magic bytes (expected 'ATFT')");
        }

        let footer_start = file_len
            .checked_sub(FOOTER_INDEX_SIZE as u64)
            .ok_or("File too small for container footer")?;

        if self.has_guide_v4() {
            let guide_end = self
                .guide_offset
                .checked_add(self.guide_len as u64)
                .ok_or("Guide offset overflow")?;
            if self.guide_offset < min_payload_end || guide_end > footer_start {
                return Err("Guide table offset overlaps payload or exceeds footer boundary");
            }
        }

        if self.has_bogon_rle() {
            let bogon_end = self
                .bogon_offset
                .checked_add(self.bogon_len as u64)
                .ok_or("Bogon offset overflow")?;
            if self.bogon_offset < min_payload_end || bogon_end > footer_start {
                return Err("Bogon filter offset overlaps payload or exceeds footer boundary");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_footer_size() {
        assert_eq!(std::mem::size_of::<ContainerFooter>(), FOOTER_INDEX_SIZE);
    }
}
