//! Stage 1 Guide Table for accelerated range lookup.
//!
//! Provides a 65,536-entry guide table indexed by the top 16 bits of an IPv4 address (`ip >> 16`).
//! Each entry maps a `/16` prefix to a compact `[start_idx..end_idx]` slice in the main interval table.
//! This narrows down multi-million record tables to $\le 64$ entries in $O(1)$ without DRAM bus thrashing.

use crate::models::{Ipv4Range, Ipv4RangeCompact};

/// An entry in the /16 Guide Table bounding the search range in the interval array.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GuideEntry {
    pub start_idx: u32,
    pub end_idx: u32,
}

impl GuideEntry {
    #[inline(always)]
    pub const fn new(start_idx: u32, end_idx: u32) -> Self {
        Self { start_idx, end_idx }
    }
}

/// A 65,536-entry Stage 1 Guide Table for IPv4 /16 prefixes.
pub struct GuideTableV4 {
    entries: Box<[GuideEntry; 65536]>,
}

impl Default for GuideTableV4 {
    fn default() -> Self {
        Self::new()
    }
}

impl GuideTableV4 {
    /// Creates an empty guide table where all /16 prefixes are empty.
    pub fn new() -> Self {
        // Allocate zeroed 65536 * 8 bytes = 512 KiB directly on heap
        let entries = vec![GuideEntry::default(); 65536]
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("Failed to allocate 65536-element GuideTable"));
        Self { entries }
    }

    /// Builds a GuideTable from a sorted slice of `ip_from` addresses (SoA layout).
    pub fn from_soa_ip_froms(ip_froms: &[u32]) -> Self {
        let mut table = Self::new();
        if ip_froms.is_empty() {
            return table;
        }

        let total = ip_froms.len() as u32;
        let mut curr_prefix = 0u16;
        let mut start_idx = 0u32;

        for (idx, &ip) in ip_froms.iter().enumerate() {
            let prefix = (ip >> 16) as u16;
            while curr_prefix < prefix {
                table.entries[curr_prefix as usize] = GuideEntry::new(start_idx, idx as u32);
                curr_prefix += 1;
                start_idx = idx as u32;
            }
        }

        while (curr_prefix as usize) < 65536 {
            table.entries[curr_prefix as usize] = GuideEntry::new(start_idx, total);
            if curr_prefix == u16::MAX {
                break;
            }
            curr_prefix += 1;
        }

        table
    }

    /// Builds a GuideTable from a sorted slice of `Ipv4RangeCompact` (AoS layout).
    pub fn from_ranges_compact(ranges: &[Ipv4RangeCompact]) -> Self {
        let mut table = Self::new();
        if ranges.is_empty() {
            return table;
        }

        let total = ranges.len() as u32;
        let mut curr_prefix = 0u16;
        let mut start_idx = 0u32;

        for (idx, r) in ranges.iter().enumerate() {
            let prefix = (r.ip_from >> 16) as u16;
            while curr_prefix < prefix {
                table.entries[curr_prefix as usize] = GuideEntry::new(start_idx, idx as u32);
                curr_prefix += 1;
                start_idx = idx as u32;
            }
        }

        while (curr_prefix as usize) < 65536 {
            table.entries[curr_prefix as usize] = GuideEntry::new(start_idx, total);
            if curr_prefix == u16::MAX {
                break;
            }
            curr_prefix += 1;
        }

        table
    }

    /// Builds a GuideTable from a sorted slice of `Ipv4Range` (Standard AoS layout).
    pub fn from_ranges_standard(ranges: &[Ipv4Range]) -> Self {
        let mut table = Self::new();
        if ranges.is_empty() {
            return table;
        }

        let total = ranges.len() as u32;
        let mut curr_prefix = 0u16;
        let mut start_idx = 0u32;

        for (idx, r) in ranges.iter().enumerate() {
            let prefix = (r.ip_from >> 16) as u16;
            while curr_prefix < prefix {
                table.entries[curr_prefix as usize] = GuideEntry::new(start_idx, idx as u32);
                curr_prefix += 1;
                start_idx = idx as u32;
            }
        }

        while (curr_prefix as usize) < 65536 {
            table.entries[curr_prefix as usize] = GuideEntry::new(start_idx, total);
            if curr_prefix == u16::MAX {
                break;
            }
            curr_prefix += 1;
        }

        table
    }

    /// Looks up the slice bounds for a given IPv4 address.
    ///
    /// Extends the lower bound by 1 if `start_idx > 0` to safely catch ranges that straddle
    /// across `/16` boundary borders.
    #[inline(always)]
    pub fn guide_bounds(&self, ip: u32, total_records: usize) -> (usize, usize) {
        let prefix = (ip >> 16) as usize;
        let entry = self.entries[prefix];
        // If range started in previous /16 and straddles boundary, widen lower bound by 1
        let start = if entry.start_idx > 0 {
            (entry.start_idx - 1) as usize
        } else {
            0
        };
        let end = (entry.end_idx as usize).min(total_records);
        let end = if end < start { start } else { end };
        (start, end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guide_table_empty() {
        let guide = GuideTableV4::from_soa_ip_froms(&[]);
        let (start, end) = guide.guide_bounds(0x01020304, 0);
        assert_eq!(start, 0);
        assert_eq!(end, 0);
    }

    #[test]
    fn test_guide_table_basic() {
        let ip_froms = [
            0x0100_0000, // 1.0.0.0 (prefix 0x0100 = 256)
            0x0100_0100, // 1.0.1.0
            0x0200_0000, // 2.0.0.0 (prefix 0x0200 = 512)
        ];
        let guide = GuideTableV4::from_soa_ip_froms(&ip_froms);

        // Query within 1.0.x.x
        let (start, end) = guide.guide_bounds(0x0100_0050, ip_froms.len());
        assert_eq!(start, 0);
        assert_eq!(end, 2);

        // Query within 2.0.x.x
        let (start, end) = guide.guide_bounds(0x0200_0010, ip_froms.len());
        assert_eq!(start, 1); // Widened by 1 for straddle safety
        assert_eq!(end, 3);
    }
}
