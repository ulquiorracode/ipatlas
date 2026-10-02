use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// 12-byte contiguous range interval mapping an IPv4 range to a normalized profile ID.
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
