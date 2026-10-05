use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MAGIC: [u8; 4] = *b"ATLS";
pub const HEADER_SIZE_V4: usize = 68;
pub const HEADER_SIZE_GEN4: usize = 68;

/// Logical container generation version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContainerVersion {
    V4 = 4,
    V5 = 5,
}

/// Record family size and indexing capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordFamily {
    /// Standard 12-byte ranges, 32-bit profile IDs.
    Standard = 0,
    /// Compact 8-byte ranges, 16-bit counts and profile IDs.
    Compact = 1,
    /// Experimental Succinct Elias-Fano representation.
    Succinct = 2,
}

/// Physical memory layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageLayout {
    /// Array of Structures: contiguous records [R0, R1, R2, ...]
    Aos = 0,
    /// Structure of Arrays: separate column arrays [ip_from, ...], [count, ...], [prof_id, ...]
    Soa = 1,
}

// ----------------------------------------------------------------------------
// Version bit-encoding matrix:
// Major (bits 8..15): 0x04 = Gen V4, 0x05 = Gen V5.
// Bit 0: Legacy compact flag (0x0401, 0x0501 = Compact AoS).
// Bit 1: Layout (0 = AoS, 1 = SoA). E.g. 0x0402 / 0x0502 = Standard SoA, 0x0403 / 0x0503 = Compact SoA.
// Or nibbles:
// 0x0400 / 0x0500: Standard AoS (also 4, 5)
// 0x0401 / 0x0501: Compact AoS (legacy compatibility alias)
// 0x0402 / 0x0502: Standard SoA
// 0x0403 / 0x0503: Compact SoA
// ----------------------------------------------------------------------------

pub const VERSION_V4_STANDARD: u16 = 4; // Legacy V4 (0x0004 or 0x0400)
pub const VERSION_V4_STANDARD_AOS: u16 = 0x0400;
pub const VERSION_V4_STANDARD_SOA: u16 = 0x0402;
pub const VERSION_V4_COMPACT_AOS: u16 = 0x0401; // Legacy 0x0401
pub const VERSION_V4_COMPACT_SOA: u16 = 0x0403;
pub const VERSION_V4_COMPACT: u16 = 0x0401; // Legacy V4.1 compact AoS compatibility alias

pub const RECORD_SIZE_V4_STANDARD: u16 = 12;
pub const RECORD_SIZE_V4_COMPACT: u16 = 8;
pub const RECORD_SIZE_IPV4_STANDARD: u16 = 12;
pub const RECORD_SIZE_IPV4_COMPACT: u16 = 8;
pub const PROFILE_SIZE_V4: usize = 20;
pub const PROFILE_SIZE_GEN4: usize = 20;

/// Header structure for IPAtlas Generation 4 databases (68 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct HeaderGen4 {
    pub magic: [u8; 4],
    pub version: u16,
    pub total_records: u32,
    pub record_size: u16,
    pub profile_count: u32,
    pub profile_offset: u32,
    pub city_count: u32,
    pub city_idx_off: u32,
    pub city_data_off: u32,
    pub city_data_len: u32,
    pub region_count: u32,
    pub region_idx_off: u32,
    pub region_data_off: u32,
    pub region_data_len: u32,
    pub isp_count: u32,
    pub isp_idx_off: u32,
    pub isp_data_off: u32,
    pub isp_data_len: u32,
}

/// Legacy alias for [`HeaderGen4`].
pub type HeaderV4 = HeaderGen4;

impl HeaderGen4 {
    #[inline(always)]
    pub fn is_soa(&self) -> bool {
        self.version == VERSION_V4_COMPACT_SOA || self.version == VERSION_V4_STANDARD_SOA
    }

    #[inline(always)]
    pub fn is_compact(&self) -> bool {
        self.record_size == RECORD_SIZE_V4_COMPACT
            || self.version == VERSION_V4_COMPACT
            || self.version == VERSION_V4_COMPACT_AOS
            || self.version == VERSION_V4_COMPACT_SOA
    }

    #[inline(always)]
    pub fn family(&self) -> RecordFamily {
        if self.is_compact() {
            RecordFamily::Compact
        } else {
            RecordFamily::Standard
        }
    }

    #[inline(always)]
    pub fn layout(&self) -> StorageLayout {
        if self.is_soa() {
            StorageLayout::Soa
        } else {
            StorageLayout::Aos
        }
    }

    /// Validates magic, version, and non-overlapping section boundary integrity.
    pub fn validate(&self, file_size: u64) -> Result<(), &'static str> {
        if self.magic != MAGIC {
            return Err("Invalid magic bytes (expected 'ATLS')");
        }

        let is_std = (self.version == VERSION_V4_STANDARD
            || self.version == VERSION_V4_STANDARD_AOS
            || self.version == VERSION_V4_STANDARD_SOA)
            && self.record_size == RECORD_SIZE_V4_STANDARD;
        let is_cmp = (self.version == VERSION_V4_COMPACT
            || self.version == VERSION_V4_COMPACT_AOS
            || self.version == VERSION_V4_COMPACT_SOA)
            && self.record_size == RECORD_SIZE_V4_COMPACT;
        if !is_std && !is_cmp {
            return Err("Unsupported database version or mismatched record size");
        }

        let total_rec = self.total_records as u64;
        let expected_records_bytes = total_rec * (self.record_size as u64);
        let ranges_end = (HEADER_SIZE_V4 as u64) + expected_records_bytes;

        let prof_offset = self.profile_offset as u64;
        if prof_offset < ranges_end {
            return Err("Profile offset overlaps range records boundary");
        }

        let total_profs = self.profile_count as u64;
        let expected_prof_bytes = total_profs * (PROFILE_SIZE_V4 as u64);
        let prof_end = prof_offset + expected_prof_bytes;

        let c_i_off = self.city_idx_off as u64;
        let c_i_len = (self.city_count as u64) * 4;
        let c_d_off = self.city_data_off as u64;
        let c_d_len = self.city_data_len as u64;

        let r_i_off = self.region_idx_off as u64;
        let r_i_len = (self.region_count as u64) * 4;
        let r_d_off = self.region_data_off as u64;
        let r_d_len = self.region_data_len as u64;

        let i_i_off = self.isp_idx_off as u64;
        let i_i_len = (self.isp_count as u64) * 4;
        let i_d_off = self.isp_data_off as u64;
        let i_d_len = self.isp_data_len as u64;

        // Verify sequential, non-overlapping section layout
        if c_i_off < prof_end
            || c_d_off < c_i_off + c_i_len
            || r_i_off < c_d_off + c_d_len
            || r_d_off < r_i_off + r_i_len
            || i_i_off < r_d_off + r_d_len
            || i_d_off < i_i_off + i_i_len
            || i_d_off + i_d_len > file_size
        {
            return Err("String blob or profile section offsets overlap or exceed file bounds");
        }

        Ok(())
    }
}

/// Generation V5: Dual-Stack layout with both IPv4 and IPv6 support.
pub const VERSION_V5_STANDARD: u16 = 5; // Legacy V5 (5 or 0x0500)
pub const VERSION_V5_STANDARD_AOS: u16 = 5;
pub const VERSION_V5_STANDARD_SOA: u16 = 0x0502;
pub const VERSION_V5_COMPACT_AOS: u16 = 0x0501; // Legacy 0x0501
pub const VERSION_V5_COMPACT_SOA: u16 = 0x0503;
pub const VERSION_V5_COMPACT: u16 = 0x0501; // Legacy V5 compact AoS compatibility alias

pub const RECORD_SIZE_V6: u16 = 36;
pub const RECORD_SIZE_IPV6_STANDARD: u16 = 36;
pub const RECORD_SIZE_IPV6_COMPACT: u16 = 16;
pub const HEADER_SIZE_V5: usize = 80;
pub const HEADER_SIZE_GEN5: usize = 80;

/// Header structure for IPAtlas Generation 5 dual-stack databases (80 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct HeaderGen5 {
    pub magic: [u8; 4],
    pub version: u16,
    pub total_records_v4: u32,
    pub record_size_v4: u16,
    pub total_records_v6: u32,
    pub record_size_v6: u16,
    pub profile_count: u32,
    pub profile_offset: u32,
    pub city_count: u32,
    pub city_idx_off: u32,
    pub city_data_off: u32,
    pub city_data_len: u32,
    pub region_count: u32,
    pub region_idx_off: u32,
    pub region_data_off: u32,
    pub region_data_len: u32,
    pub isp_count: u32,
    pub isp_idx_off: u32,
    pub isp_data_off: u32,
    pub isp_data_len: u32,
    pub reserved: u16,
    pub crc32: u32,
}

/// Legacy alias for [`HeaderGen5`].
pub type HeaderV5 = HeaderGen5;

/// Header flags bitmask stored in `HeaderGen5::reserved`.
pub const HEADER_FLAG_EMBEDDED_ZSTD: u16 = 1 << 2;

impl HeaderGen5 {
    #[inline(always)]
    pub fn is_soa(&self) -> bool {
        self.version == VERSION_V5_COMPACT_SOA || self.version == VERSION_V5_STANDARD_SOA
    }

    #[inline(always)]
    pub fn is_compact_v4(&self) -> bool {
        self.record_size_v4 == RECORD_SIZE_V4_COMPACT
            || self.version == VERSION_V5_COMPACT
            || self.version == VERSION_V5_COMPACT_AOS
            || self.version == VERSION_V5_COMPACT_SOA
    }

    #[inline(always)]
    pub fn is_compact_v6(&self) -> bool {
        self.record_size_v6 == RECORD_SIZE_IPV6_COMPACT
    }

    #[inline(always)]
    pub fn family(&self) -> RecordFamily {
        if self.is_compact_v4() {
            RecordFamily::Compact
        } else {
            RecordFamily::Standard
        }
    }

    #[inline(always)]
    pub fn layout(&self) -> StorageLayout {
        if self.is_soa() {
            StorageLayout::Soa
        } else {
            StorageLayout::Aos
        }
    }

    /// Returns true if the payload following the header is compressed via embedded Zstandard.
    #[inline(always)]
    pub fn is_embedded_zstd(&self) -> bool {
        (self.reserved & HEADER_FLAG_EMBEDDED_ZSTD) != 0
    }

    /// Validates magic, version, section offsets and file size.
    pub fn validate(&self, file_size: u64) -> Result<(), &'static str> {
        if self.magic != MAGIC {
            return Err("Invalid magic bytes (expected 'ATLS')");
        }

        let is_std = (self.version == VERSION_V5_STANDARD
            || self.version == VERSION_V5_STANDARD_AOS
            || self.version == VERSION_V5_STANDARD_SOA)
            && self.record_size_v4 == RECORD_SIZE_V4_STANDARD;
        let is_cmp = (self.version == VERSION_V5_COMPACT
            || self.version == VERSION_V5_COMPACT_AOS
            || self.version == VERSION_V5_COMPACT_SOA)
            && self.record_size_v4 == RECORD_SIZE_V4_COMPACT;
        if !is_std && !is_cmp {
            return Err("Unsupported Generation V5 version or mismatched record size");
        }

        if self.total_records_v6 > 0
            && self.record_size_v6 != RECORD_SIZE_IPV6_STANDARD
            && self.record_size_v6 != RECORD_SIZE_IPV6_COMPACT
        {
            return Err("Invalid IPv6 record size (expected 36 bytes or 16 bytes for Split-64)");
        }

        let v4_bytes = (self.total_records_v4 as u64) * (self.record_size_v4 as u64);
        let v6_bytes = (self.total_records_v6 as u64) * (self.record_size_v6 as u64);
        let ranges_end = (HEADER_SIZE_V5 as u64) + v4_bytes + v6_bytes;

        let prof_offset = self.profile_offset as u64;
        if prof_offset < ranges_end {
            return Err("Profile offset overlaps range records boundary");
        }

        let total_profs = self.profile_count as u64;
        let expected_prof_bytes = total_profs * (PROFILE_SIZE_V4 as u64);
        let prof_end = prof_offset + expected_prof_bytes;

        let c_i_off = self.city_idx_off as u64;
        let c_i_len = (self.city_count as u64) * 4;
        let c_d_off = self.city_data_off as u64;
        let c_d_len = self.city_data_len as u64;

        let r_i_off = self.region_idx_off as u64;
        let r_i_len = (self.region_count as u64) * 4;
        let r_d_off = self.region_data_off as u64;
        let r_d_len = self.region_data_len as u64;

        let i_i_off = self.isp_idx_off as u64;
        let i_i_len = (self.isp_count as u64) * 4;
        let i_d_off = self.isp_data_off as u64;
        let i_d_len = self.isp_data_len as u64;

        // Verify sequential, non-overlapping section layout
        if c_i_off < prof_end
            || c_d_off < c_i_off + c_i_len
            || r_i_off < c_d_off + c_d_len
            || r_d_off < r_i_off + r_i_len
            || i_i_off < r_d_off + r_d_len
            || i_d_off < i_i_off + i_i_len
            || i_d_off + i_d_len > file_size
        {
            return Err("String blob or profile section offsets overlap or exceed file bounds");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_sizes() {
        assert_eq!(std::mem::size_of::<HeaderV4>(), HEADER_SIZE_V4);
        assert_eq!(std::mem::size_of::<HeaderV5>(), HEADER_SIZE_V5);
    }
}
