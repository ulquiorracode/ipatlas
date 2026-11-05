//! IPAtlas Generation 6 models leveraging `narrow-ptr`, `odd-int`, and `stitch-data`.
//!
//! Conforms to the "Scrooge" Systems Mindset:
//! - Contiguous compact records.
//! - Relative displacements into embedded string and profile arenas.
//! - Monomorphic zero-copy reading without heap allocations on hot paths.

use narrow_ptr::{RelPtr, ScaledRelPtr};
use odd_int::I24;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Generation 6 standard IPv4 range entry (10 bytes total vs 12 bytes legacy).
///
/// Layout:
/// - `ip_from`: 4 bytes (u32)
/// - `ip_to`: 4 bytes (u32)
/// - `profile_offset`: 2 bytes (i16) relative displacement to `ProfileGen6`
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct Ipv4RangeV6 {
    pub ip_from: u32,
    pub ip_to: u32,
    pub profile_offset: i16,
}

impl Ipv4RangeV6 {
    #[inline(always)]
    pub const fn new(ip_from: u32, ip_to: u32, profile_offset: i16) -> Self {
        Self {
            ip_from,
            ip_to,
            profile_offset,
        }
    }

    #[inline(always)]
    pub fn contains(&self, ip: u32) -> bool {
        ip >= self.ip_from && ip <= self.ip_to
    }

    #[inline(always)]
    pub fn profile_ptr(&self) -> RelPtr<ProfileGen6, i16> {
        RelPtr::from_raw_offset(self.profile_offset)
    }
}

/// Generation 6 Compact 7-byte IPv4 range entry.
///
/// In contiguous partitioning, each range's upper bound is implicitly defined by
/// the next record's `ip_from - 1`. Storing only `ip_from` and a 24-bit relative profile offset
/// drops the record size down to **7 bytes**, allowing **9 records per 64-byte L1D cache line**
/// (compared to 5 records for 12B Gen 4 and 8 records for 8B Gen 4.1).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct Ipv4RangeV6Compact {
    pub ip_from: u32,
    pub profile_offset: I24,
}

impl Ipv4RangeV6Compact {
    #[inline(always)]
    pub const fn new(ip_from: u32, profile_offset: I24) -> Self {
        Self {
            ip_from,
            profile_offset,
        }
    }

    #[inline(always)]
    pub fn profile_rel_ptr(&self) -> RelPtr<ProfileGen6, I24> {
        RelPtr::from_raw_offset(self.profile_offset)
    }
}

/// Generation 6 normalized standard profile record (16 bytes).
///
/// Fits exactly 4 profiles per 64-byte L1D cache line (0 bytes cache line straddling).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ProfileGen6 {
    pub asn: u32,
    pub flags: u16,
    pub country: [u8; 2],
    pub lat_fixed: i16,
    pub lon_fixed: i16,
    pub city_offset: I24,
    pub isp_offset: I24,
}

impl ProfileGen6 {
    #[inline(always)]
    pub const fn new(
        asn: u32,
        flags: u16,
        country: [u8; 2],
        lat_fixed: i16,
        lon_fixed: i16,
        city_offset: I24,
        isp_offset: I24,
    ) -> Self {
        Self {
            asn,
            flags,
            country,
            lat_fixed,
            lon_fixed,
            city_offset,
            isp_offset,
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
    pub fn city_rel_ptr(&self) -> RelPtr<u8, I24> {
        RelPtr::from_raw_offset(self.city_offset)
    }

    #[inline(always)]
    pub fn isp_rel_ptr(&self) -> RelPtr<u8, I24> {
        RelPtr::from_raw_offset(self.isp_offset)
    }
}

/// Generation 6 Edge / Security profile record (8 bytes).
///
/// Designed for high-throughput firewall, anti-DDoS, and reverse proxy threat-mitigation.
/// Omits geographic coordinates and string pointers.
/// Fits **exactly 8 profiles per 64-byte L1D cache line** (100% mechanical sympathy).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ProfileGen6Edge {
    pub asn: u32,
    pub flags: u16,
    pub country: [u8; 2],
}

impl ProfileGen6Edge {
    #[inline(always)]
    pub const fn new(asn: u32, flags: u16, country: [u8; 2]) -> Self {
        Self {
            asn,
            flags,
            country,
        }
    }
}

/// Generation 6 Compact Geo profile record (12 bytes).
///
/// Retains ASN, security flags, ISO country code, and compact 16-bit 4-byte-aligned
/// scaled string pointers (`ScaledRelPtr<u8, i16, 2>`) covering $\pm 128\text{ KB}$ string pools.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ProfileGen6Compact {
    pub asn: u32,
    pub flags: u16,
    pub country: [u8; 2],
    pub city_offset: i16,
    pub isp_offset: i16,
}

impl ProfileGen6Compact {
    #[inline(always)]
    pub const fn new(
        asn: u32,
        flags: u16,
        country: [u8; 2],
        city_offset: i16,
        isp_offset: i16,
    ) -> Self {
        Self {
            asn,
            flags,
            country,
            city_offset,
            isp_offset,
        }
    }

    #[inline(always)]
    pub fn city_rel_ptr(&self) -> ScaledRelPtr<u8, i16, 2> {
        ScaledRelPtr::from_raw_offset(self.city_offset)
    }

    #[inline(always)]
    pub fn isp_rel_ptr(&self) -> ScaledRelPtr<u8, i16, 2> {
        ScaledRelPtr::from_raw_offset(self.isp_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn test_gen6_exact_memory_sizes() {
        assert_eq!(size_of::<Ipv4RangeV6>(), 10);
        assert_eq!(size_of::<Ipv4RangeV6Compact>(), 7);
        assert_eq!(size_of::<ProfileGen6>(), 18);
        assert_eq!(size_of::<ProfileGen6Edge>(), 8);
        assert_eq!(size_of::<ProfileGen6Compact>(), 12);
    }
}
