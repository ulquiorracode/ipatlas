use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// 20-byte normalized metadata profile for an IP range.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ProfileV4 {
    pub city_idx: u32,
    pub asn: u32,
    pub country: [u8; 2],
    pub reg_idx: u16,
    pub isp_idx: u16,
    pub flags: u16,
    pub lat_fixed: i16,
    pub lon_fixed: i16,
}

impl ProfileV4 {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        city_idx: u32,
        asn: u32,
        country: [u8; 2],
        reg_idx: u16,
        isp_idx: u16,
        flags: u16,
        lat_fixed: i16,
        lon_fixed: i16,
    ) -> Self {
        Self {
            city_idx,
            asn,
            country,
            reg_idx,
            isp_idx,
            flags,
            lat_fixed,
            lon_fixed,
        }
    }

    #[inline(always)]
    pub fn latitude(&self) -> f32 {
        (self.lat_fixed as f32) / 100.0
    }

    #[inline(always)]
    pub fn longitude(&self) -> f32 {
        (self.lon_fixed as f32) / 100.0
    }

    #[inline(always)]
    pub fn country_code(&self) -> &str {
        std::str::from_utf8(&self.country).unwrap_or("--")
    }
}
