//! IPAtlas Generation 6 Readers (Standard, Edge, and Geo Compact).
//!
//! Conforms to the "Scrooge" Systems Mindset:
//! - Direct memory-mapped access over `.stitch` container records.
//! - Resolves relative pointers in constant time ($O(1)$) with zero heap allocation.

use crate::models::{
    Ipv4RangeV6, Ipv4RangeV6Compact, ProfileGen6, ProfileGen6Compact, ProfileGen6Edge,
};

/// Generation 6 Standard reader over raw memory slices.
pub struct Gen6Reader<'a> {
    ranges: &'a [Ipv4RangeV6],
    profiles: &'a [ProfileGen6],
    string_blob: &'a [u8],
}

impl<'a> Gen6Reader<'a> {
    /// Initializes a Gen6 reader from slices.
    pub fn new(
        ranges: &'a [Ipv4RangeV6],
        profiles: &'a [ProfileGen6],
        string_blob: &'a [u8],
    ) -> Self {
        Self {
            ranges,
            profiles,
            string_blob,
        }
    }

    /// Number of IPv4 ranges in the database.
    #[inline(always)]
    pub fn total_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Binary search for an IPv4 address.
    #[inline]
    pub fn lookup_v4(
        &self,
        ip: u32,
    ) -> Option<(&'a Ipv4RangeV6, &'a ProfileGen6, &'a str, &'a str)> {
        let idx = match self.ranges.binary_search_by(|range| {
            if ip < range.ip_from {
                core::cmp::Ordering::Greater
            } else if ip > range.ip_to {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        }) {
            Ok(i) => i,
            Err(_) => return None,
        };

        let range = &self.ranges[idx];
        let profile_idx = (range.profile_offset as isize) as usize;
        let profile = self.profiles.get(profile_idx)?;

        let city_off = profile.city_offset.to_isize();
        let isp_off = profile.isp_offset.to_isize();

        let city = if city_off >= 0 && (city_off as usize) < self.string_blob.len() {
            let slice = &self.string_blob[city_off as usize..];
            let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            core::str::from_utf8(&slice[..len]).unwrap_or("")
        } else {
            ""
        };

        let isp = if isp_off >= 0 && (isp_off as usize) < self.string_blob.len() {
            let slice = &self.string_blob[isp_off as usize..];
            let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            core::str::from_utf8(&slice[..len]).unwrap_or("")
        } else {
            ""
        };

        Some((range, profile, city, isp))
    }
}

/// Generation 6 Compact reader with 7-byte ranges (`Ipv4RangeV6Compact`).
///
/// Supports generic profile representations (`ProfileGen6Edge` 8B or `ProfileGen6Compact` 12B).
pub struct Gen6CompactReader<'a, P> {
    ranges: &'a [Ipv4RangeV6Compact],
    profiles: &'a [P],
    string_blob: &'a [u8],
}

impl<'a, P> Gen6CompactReader<'a, P> {
    pub fn new(ranges: &'a [Ipv4RangeV6Compact], profiles: &'a [P], string_blob: &'a [u8]) -> Self {
        Self {
            ranges,
            profiles,
            string_blob,
        }
    }

    #[inline(always)]
    pub fn total_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Finds the range record containing `ip` using branchless partition binary search.
    #[inline]
    fn find_index(&self, ip: u32) -> Option<usize> {
        let len = self.ranges.len();
        if len == 0 {
            return None;
        }

        // Binary search to find greatest ip_from <= ip
        let mut low = 0;
        let mut high = len;
        while low < high {
            let mid = low + (high - low) / 2;
            if self.ranges[mid].ip_from <= ip {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        if low > 0 {
            Some(low - 1)
        } else {
            None
        }
    }
}

impl<'a> Gen6CompactReader<'a, ProfileGen6Edge> {
    /// Fast security / edge lookup returning (asn, flags, country).
    #[inline]
    pub fn lookup_edge(&self, ip: u32) -> Option<(&'a Ipv4RangeV6Compact, &'a ProfileGen6Edge)> {
        let idx = self.find_index(ip)?;
        let range = &self.ranges[idx];
        let prof_idx = range.profile_offset.to_isize() as usize;
        let profile = self.profiles.get(prof_idx)?;
        Some((range, profile))
    }
}

impl<'a> Gen6CompactReader<'a, ProfileGen6Compact> {
    /// Full geographic compact lookup with 12-byte profile and 4-byte scaled strings.
    #[inline]
    pub fn lookup_geo(
        &self,
        ip: u32,
    ) -> Option<(
        &'a Ipv4RangeV6Compact,
        &'a ProfileGen6Compact,
        &'a str,
        &'a str,
    )> {
        let idx = self.find_index(ip)?;
        let range = &self.ranges[idx];
        let prof_idx = range.profile_offset.to_isize() as usize;
        let profile = self.profiles.get(prof_idx)?;

        let city_off = (profile.city_offset as isize) << 2;
        let isp_off = (profile.isp_offset as isize) << 2;

        let city = if city_off >= 0 && (city_off as usize) < self.string_blob.len() {
            let slice = &self.string_blob[city_off as usize..];
            let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            core::str::from_utf8(&slice[..len]).unwrap_or("")
        } else {
            ""
        };

        let isp = if isp_off >= 0 && (isp_off as usize) < self.string_blob.len() {
            let slice = &self.string_blob[isp_off as usize..];
            let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            core::str::from_utf8(&slice[..len]).unwrap_or("")
        } else {
            ""
        };

        Some((range, profile, city, isp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odd_int::I24;

    #[test]
    fn test_gen6_reader_lookup() {
        let profiles = [ProfileGen6::new(
            13335,
            0x01,
            *b"US",
            3775,
            -12242,
            I24::from_i64(0).unwrap(),
            I24::from_i64(14).unwrap(),
        )];

        let ranges = [
            Ipv4RangeV6::new(16777216, 16777471, 0),
            Ipv4RangeV6::new(16777472, 16777727, 0),
        ];

        let string_blob = b"San Francisco\0Cloudflare Inc.\0";

        let reader = Gen6Reader::new(&ranges, &profiles, string_blob);
        assert_eq!(reader.total_ranges(), 2);

        let hit = reader.lookup_v4(16777220);
        assert!(hit.is_some());
        let (_, prof, city, isp) = hit.unwrap();
        let asn = prof.asn;
        assert_eq!(asn, 13335);
        assert_eq!(city, "San Francisco");
        assert_eq!(isp, "Cloudflare Inc.");

        assert!(reader.lookup_v4(100).is_none());
    }

    #[test]
    fn test_gen6_compact_edge_lookup() {
        let edge_profiles = [
            ProfileGen6Edge::new(13335, 0x01, *b"US"),
            ProfileGen6Edge::new(15169, 0x02, *b"IE"),
        ];

        let ranges = [
            Ipv4RangeV6Compact::new(16777216, I24::from_i64(0).unwrap()),
            Ipv4RangeV6Compact::new(16777472, I24::from_i64(1).unwrap()),
        ];

        let reader = Gen6CompactReader::new(&ranges, &edge_profiles, &[]);
        let hit = reader.lookup_edge(16777220);
        assert!(hit.is_some());
        let (_, prof) = hit.unwrap();
        let asn = prof.asn;
        assert_eq!(asn, 13335);

        let hit2 = reader.lookup_edge(16777500);
        assert!(hit2.is_some());
        let (_, prof2) = hit2.unwrap();
        let asn2 = prof2.asn;
        assert_eq!(asn2, 15169);
    }
}
