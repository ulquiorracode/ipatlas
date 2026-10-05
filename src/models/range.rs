use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Standard 12-byte contiguous range interval mapping an IPv4 range to a 32-bit profile ID.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct Ipv4Range {
    pub ip_from: u32,
    pub ip_to: u32,
    pub profile_id: u32,
}

impl Ipv4Range {
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

/// Legacy alias for [`Ipv4Range`].
pub type RangeV4 = Ipv4Range;

/// Compact 8-byte range interval (Format V4.1 Compact) optimized for L1/L2 cache lines (8 records per 64-byte line).
/// Suitable for datasets with <= 65,535 profiles and interval lengths <= 65,535.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct Ipv4RangeCompact {
    pub ip_from: u32,
    pub count: u16,
    pub profile_id: u16,
}

impl Ipv4RangeCompact {
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

/// Legacy alias for [`Ipv4RangeCompact`].
pub type RangeV4Compact = Ipv4RangeCompact;

/// 36-byte uncompressed IPv6 range interval mapping a 128-bit address range to a 32-bit profile ID.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct Ipv6Range {
    pub ip_from: u128,
    pub ip_to: u128,
    pub profile_id: u32,
}

impl Ipv6Range {
    #[inline(always)]
    pub const fn new(ip_from: u128, ip_to: u128, profile_id: u32) -> Self {
        Self {
            ip_from,
            ip_to,
            profile_id,
        }
    }

    #[inline(always)]
    pub fn contains(&self, ip: u128) -> bool {
        ip >= self.ip_from && ip <= self.ip_to
    }
}

/// Legacy alias for [`Ipv6Range`].
pub type RangeV6 = Ipv6Range;

/// Compact 16-byte IPv6 range interval using Split-64 Truncation.
///
/// In global BGP and GeoIP routing, IPv6 allocations are bounded to /64 subnets or larger.
/// The lower 64 bits (Interface ID) belong to the same autonomous system, ISP, and geographic centroid.
/// By storing the upper 64 bits (`ip_from_hi`) and a 32-bit count of /64 blocks (`count_hi`),
/// the entry shrinks from 36 bytes down to exactly 16 bytes:
///
/// - Fits exactly 4 records per 64-byte CPU cache line (0% cache-line straddling).
/// - 2.25x density improvement over uncompressed 36-byte [`Ipv6Range`].
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct Ipv6RangeSplit64 {
    /// Upper 64 bits of the starting IPv6 address (`ip_from >> 64`).
    pub ip_from_hi: u64,
    /// Number of contiguous /64 subnets covered by this interval (`(ip_to >> 64) - (ip_from >> 64)`).
    pub count_hi: u32,
    /// 32-bit index into the normalized metadata profile pool.
    pub profile_id: u32,
}

impl Ipv6RangeSplit64 {
    #[inline(always)]
    pub const fn new(ip_from_hi: u64, count_hi: u32, profile_id: u32) -> Self {
        Self {
            ip_from_hi,
            count_hi,
            profile_id,
        }
    }

    /// Computes the upper 64 bits of the end IP address.
    #[inline(always)]
    pub fn ip_to_hi(&self) -> u64 {
        self.ip_from_hi.saturating_add(self.count_hi as u64)
    }

    /// Evaluates if an IPv6 address (or its upper 64-bit word) is contained within this /64 interval.
    #[inline(always)]
    pub fn contains_hi(&self, ip_hi: u64) -> bool {
        ip_hi >= self.ip_from_hi && ip_hi <= self.ip_to_hi()
    }

    /// Evaluates if a full 128-bit IPv6 address is contained within this interval.
    #[inline(always)]
    pub fn contains(&self, ip: u128) -> bool {
        let ip_hi = (ip >> 64) as u64;
        self.contains_hi(ip_hi)
    }
}

/// Compact 16-byte alias for [`Ipv6RangeSplit64`].
pub type Ipv6RangeCompact = Ipv6RangeSplit64;
