use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MAGIC: [u8; 4] = *b"ATLS";
pub const HEADER_SIZE_V4: usize = 68;
pub const VERSION_V4: u16 = 4;
pub const RECORD_SIZE_V4: u16 = 12;
pub const PROFILE_SIZE_V4: usize = 20;

/// Header structure for IPAtlas Version 4 databases (68 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct HeaderV4 {
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

impl HeaderV4 {
    /// Validates magic and version consistency.
    pub fn validate(&self, file_size: u64) -> Result<(), &'static str> {
        if self.magic != MAGIC {
            return Err("Invalid magic bytes (expected 'ATLS')");
        }
        if self.version != VERSION_V4 {
            return Err("Unsupported database version");
        }
        if self.record_size != RECORD_SIZE_V4 {
            return Err("Invalid record size for V4 layout (expected 12 bytes)");
        }
        let total_rec = self.total_records as u64;
        let expected_records_bytes = total_rec * (self.record_size as u64);
        let prof_offset = self.profile_offset as u64;
        if prof_offset < HEADER_SIZE_V4 as u64 + expected_records_bytes {
            return Err("Profile offset precedes range records boundary");
        }
        let total_profs = self.profile_count as u64;
        let expected_prof_bytes = total_profs * (PROFILE_SIZE_V4 as u64);
        if file_size < prof_offset + expected_prof_bytes {
            return Err("File size is smaller than expected profile table boundary");
        }
        Ok(())
    }
}
