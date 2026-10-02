use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Standard 12-byte contiguous range interval mapping an IPv4 range to a 32-bit profile ID.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RangeV4 {
    pub ip_from: u32,
    pub ip_to: u32,
    pub profile_id: u32,
}

impl RangeV4 {
    #[inline(always)]
    pub const fn new(ip_from: u32, ip_to: u32, profile_id: u32) -> Self {
        Self {
            ip_from,
            ip_to,
            profile_id,
        }
    }

    #[inline(always)]
    pub fn contains(&self, ip: u32) -> bool {
        ip >= self.ip_from && ip <= self.ip_to
    }
}

/// Compact 8-byte range interval (Format V4.1 Compact) optimized for L1/L2 cache lines (8 records per 64-byte line).
/// Suitable for datasets with <= 65,535 profiles and interval lengths <= 65,535.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RangeV4Compact {
    pub ip_from: u32,
    pub count: u16,
    pub profile_id: u16,
}

impl RangeV4Compact {
    #[inline(always)]
    pub const fn new(ip_from: u32, count: u16, profile_id: u16) -> Self {
        Self {
            ip_from,
            count,
            profile_id,
        }
    }

    #[inline(always)]
    pub fn ip_to(&self) -> u32 {
        self.ip_from.saturating_add(self.count as u32)
    }

    #[inline(always)]
    pub fn contains(&self, ip: u32) -> bool {
        ip >= self.ip_from && ip <= self.ip_to()
    }
}
