use memmap2::Mmap;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use thiserror::Error;
use zerocopy::FromBytes;

use crate::models::{
    compute_crc32, GeoFlags, GeoRecord, GeoRecordRef, HeaderV4, HeaderV5, ProfileV4, RangeV4,
    RangeV4Compact, RangeV6, HEADER_SIZE_V4, HEADER_SIZE_V5, MAGIC, PROFILE_SIZE_V4,
    RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD, RECORD_SIZE_V6, VERSION_V4_COMPACT,
    VERSION_V4_STANDARD, VERSION_V5_COMPACT, VERSION_V5_STANDARD,
};

#[derive(Error, Debug)]
pub enum ReaderError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database file is too small: {0} bytes")]
    FileTooSmall(u64),
    #[error("Corrupted database: {0}")]
    Corrupted(&'static str),
    #[error("CRC32 mismatch: expected {expected:#010x}, calculated {actual:#010x}")]
    CrcMismatch { expected: u32, actual: u32 },
    #[error("Unsupported database version: {0:#06x}")]
    UnsupportedVersion(u16),
    #[error("Decompression error: {0}")]
    Decompression(String),
}

#[derive(Clone, Copy, Debug)]
pub enum HeaderVariant {
    V4(HeaderV4),
    V5(HeaderV5),
}

/// Backing storage for zero-copy views: either a zero-copy memory mapping or an in-memory buffer.
pub enum StorageBuffer {
    Mmap(Mmap),
    Memory(Vec<u8>),
}

impl std::ops::Deref for StorageBuffer {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &[u8] {
        match self {
            Self::Mmap(m) => m,
            Self::Memory(v) => v,
        }
    }
}

/// Zero-copy memory-mapped IPAtlas database reader supporting Generation V4 and V5 (Dual-Stack).
/// Completely sound and safe: holds the storage allocation and computes verified zerocopy slices on the fly.
pub struct IpAtlasReader {
    mmap: StorageBuffer,
    header: HeaderVariant,
}

impl IpAtlasReader {
    /// Opens and memory-maps an IPAtlas database from disk.
    /// If the database has `EMBEDDED_ZSTD` set in its header flags, its payload
    /// is transparently decompressed into memory upon opening.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ReaderError> {
        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        if file_len < HEADER_SIZE_V4 as u64 {
            return Err(ReaderError::FileTooSmall(file_len));
        }

        let mmap = unsafe { Mmap::map(&file)? };
        Self::from_mmap(mmap, file_len)
    }

    /// Constructs reader from an existing memory mapping.
    pub fn from_mmap(mmap: Mmap, file_len: u64) -> Result<Self, ReaderError> {
        if file_len < 6 {
            return Err(ReaderError::FileTooSmall(file_len));
        }

        if mmap[..4] != MAGIC {
            return Err(ReaderError::Corrupted(
                "Invalid magic bytes (expected 'ATLS')",
            ));
        }

        let version = u16::from_le_bytes([mmap[4], mmap[5]]);

        let (header, storage) = match version {
            VERSION_V5_STANDARD | VERSION_V5_COMPACT => {
                if file_len < HEADER_SIZE_V5 as u64 {
                    return Err(ReaderError::FileTooSmall(file_len));
                }
                let h = HeaderV5::read_from_bytes(&mmap[..HEADER_SIZE_V5])
                    .map_err(|_| ReaderError::Corrupted("Failed to parse V5 header bytes"))?;

                if h.is_embedded_zstd() {
                    let decompressed_payload = zstd::stream::decode_all(&mmap[HEADER_SIZE_V5..])
                        .map_err(|e| ReaderError::Decompression(e.to_string()))?;
                    let total_uncompressed_len =
                        (HEADER_SIZE_V5 + decompressed_payload.len()) as u64;
                    h.validate(total_uncompressed_len)
                        .map_err(ReaderError::Corrupted)?;

                    let mut full_buf =
                        Vec::with_capacity(HEADER_SIZE_V5 + decompressed_payload.len());
                    full_buf.extend_from_slice(&mmap[..HEADER_SIZE_V5]);
                    full_buf.extend_from_slice(&decompressed_payload);
                    (HeaderVariant::V5(h), StorageBuffer::Memory(full_buf))
                } else {
                    h.validate(file_len).map_err(ReaderError::Corrupted)?;
                    (HeaderVariant::V5(h), StorageBuffer::Mmap(mmap))
                }
            }
            VERSION_V4_STANDARD | VERSION_V4_COMPACT => {
                let h = HeaderV4::read_from_bytes(&mmap[..HEADER_SIZE_V4])
                    .map_err(|_| ReaderError::Corrupted("Failed to parse V4 header bytes"))?;
                h.validate(file_len).map_err(ReaderError::Corrupted)?;
                (HeaderVariant::V4(h), StorageBuffer::Mmap(mmap))
            }
            other => return Err(ReaderError::UnsupportedVersion(other)),
        };

        let reader = Self {
            mmap: storage,
            header,
        };

        // Pre-validate slices
        match &reader.header {
            HeaderVariant::V4(h) => {
                if h.is_compact() {
                    let start = HEADER_SIZE_V4;
                    let end =
                        start + (h.total_records as usize) * (RECORD_SIZE_V4_COMPACT as usize);
                    <[RangeV4Compact]>::ref_from_bytes(&reader.mmap[start..end]).map_err(|_| {
                        ReaderError::Corrupted("Unaligned or invalid RangeV4Compact slice")
                    })?;
                } else {
                    let start = HEADER_SIZE_V4;
                    let end =
                        start + (h.total_records as usize) * (RECORD_SIZE_V4_STANDARD as usize);
                    <[RangeV4]>::ref_from_bytes(&reader.mmap[start..end]).map_err(|_| {
                        ReaderError::Corrupted("Unaligned or invalid RangeV4 slice")
                    })?;
                }

                let prof_start = h.profile_offset as usize;
                let prof_end = prof_start + (h.profile_count as usize) * PROFILE_SIZE_V4;
                <[ProfileV4]>::ref_from_bytes(&reader.mmap[prof_start..prof_end])
                    .map_err(|_| ReaderError::Corrupted("Unaligned or invalid ProfileV4 slice"))?;
            }
            HeaderVariant::V5(h) => {
                let v4_start = HEADER_SIZE_V5;
                let v4_end = v4_start + (h.total_records_v4 as usize) * (h.record_size_v4 as usize);
                if h.is_compact_v4() {
                    <[RangeV4Compact]>::ref_from_bytes(&reader.mmap[v4_start..v4_end]).map_err(
                        |_| ReaderError::Corrupted("Unaligned or invalid RangeV4Compact slice"),
                    )?;
                } else {
                    <[RangeV4]>::ref_from_bytes(&reader.mmap[v4_start..v4_end]).map_err(|_| {
                        ReaderError::Corrupted("Unaligned or invalid RangeV4 slice")
                    })?;
                }

                let v6_start = v4_end;
                let v6_end = v6_start + (h.total_records_v6 as usize) * (h.record_size_v6 as usize);
                <[RangeV6]>::ref_from_bytes(&reader.mmap[v6_start..v6_end])
                    .map_err(|_| ReaderError::Corrupted("Unaligned or invalid RangeV6 slice"))?;

                let prof_start = h.profile_offset as usize;
                let prof_end = prof_start + (h.profile_count as usize) * PROFILE_SIZE_V4;
                <[ProfileV4]>::ref_from_bytes(&reader.mmap[prof_start..prof_end])
                    .map_err(|_| ReaderError::Corrupted("Unaligned or invalid ProfileV4 slice"))?;
            }
        }

        Ok(reader)
    }

    /// Verifies CRC32 checksum of the database against the header checksum (Generation V5).
    pub fn validate_checksum(&self) -> Result<(), ReaderError> {
        if let HeaderVariant::V5(h) = &self.header {
            let actual = compute_crc32(&self.mmap[HEADER_SIZE_V5..]);
            if actual != h.crc32 {
                return Err(ReaderError::CrcMismatch {
                    expected: h.crc32,
                    actual,
                });
            }
        }
        Ok(())
    }

    /// Total count of all IP interval ranges (IPv4 + IPv6).
    #[inline(always)]
    pub fn len(&self) -> usize {
        match &self.header {
            HeaderVariant::V4(h) => h.total_records as usize,
            HeaderVariant::V5(h) => (h.total_records_v4 + h.total_records_v6) as usize,
        }
    }

    /// Number of IPv4 intervals.
    #[inline(always)]
    pub fn len_v4(&self) -> usize {
        match &self.header {
            HeaderVariant::V4(h) => h.total_records as usize,
            HeaderVariant::V5(h) => h.total_records_v4 as usize,
        }
    }

    /// Number of IPv6 intervals.
    #[inline(always)]
    pub fn len_v6(&self) -> usize {
        match &self.header {
            HeaderVariant::V4(_) => 0,
            HeaderVariant::V5(h) => h.total_records_v6 as usize,
        }
    }

    /// Returns true if the database contains zero intervals.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Database format version.
    #[inline(always)]
    pub fn version(&self) -> u16 {
        match &self.header {
            HeaderVariant::V4(h) => h.version,
            HeaderVariant::V5(h) => h.version,
        }
    }

    /// Stored CRC32 checksum, if Generation V5.
    #[inline(always)]
    pub fn crc32(&self) -> Option<u32> {
        match &self.header {
            HeaderVariant::V4(_) => None,
            HeaderVariant::V5(h) => Some(h.crc32),
        }
    }

    /// Returns true if the database is in Compact layout.
    #[inline(always)]
    pub fn is_compact(&self) -> bool {
        match &self.header {
            HeaderVariant::V4(h) => h.is_compact(),
            HeaderVariant::V5(h) => h.is_compact_v4(),
        }
    }

    /// Returns true if the database was packaged with embedded Zstandard compression.
    #[inline(always)]
    pub fn is_embedded_zstd(&self) -> bool {
        match &self.header {
            HeaderVariant::V4(_) => false,
            HeaderVariant::V5(h) => h.is_embedded_zstd(),
        }
    }

    /// Total count of unique normalized metadata profiles.
    #[inline(always)]
    pub fn profile_count(&self) -> usize {
        match &self.header {
            HeaderVariant::V4(h) => h.profile_count as usize,
            HeaderVariant::V5(h) => h.profile_count as usize,
        }
    }

    /// City dictionary entry count.
    #[inline(always)]
    pub fn city_count(&self) -> usize {
        match &self.header {
            HeaderVariant::V4(h) => h.city_count as usize,
            HeaderVariant::V5(h) => h.city_count as usize,
        }
    }

    /// Region dictionary entry count.
    #[inline(always)]
    pub fn region_count(&self) -> usize {
        match &self.header {
            HeaderVariant::V4(h) => h.region_count as usize,
            HeaderVariant::V5(h) => h.region_count as usize,
        }
    }

    /// ISP dictionary entry count.
    #[inline(always)]
    pub fn isp_count(&self) -> usize {
        match &self.header {
            HeaderVariant::V4(h) => h.isp_count as usize,
            HeaderVariant::V5(h) => h.isp_count as usize,
        }
    }

    /// Zero-copy verified slice of standard V4 ranges (12 bytes per record).
    #[inline(always)]
    pub fn ranges(&self) -> &[RangeV4] {
        match &self.header {
            HeaderVariant::V4(h) => {
                if h.is_compact() {
                    &[]
                } else {
                    let start = HEADER_SIZE_V4;
                    let end =
                        start + (h.total_records as usize) * (RECORD_SIZE_V4_STANDARD as usize);
                    <[RangeV4]>::ref_from_bytes(&self.mmap[start..end]).unwrap_or(&[])
                }
            }
            HeaderVariant::V5(h) => {
                if h.is_compact_v4() {
                    &[]
                } else {
                    let start = HEADER_SIZE_V5;
                    let end =
                        start + (h.total_records_v4 as usize) * (RECORD_SIZE_V4_STANDARD as usize);
                    <[RangeV4]>::ref_from_bytes(&self.mmap[start..end]).unwrap_or(&[])
                }
            }
        }
    }

    /// Zero-copy verified slice of compact V4 ranges (8 bytes per record).
    #[inline(always)]
    pub fn ranges_compact(&self) -> &[RangeV4Compact] {
        match &self.header {
            HeaderVariant::V4(h) => {
                if h.is_compact() {
                    let start = HEADER_SIZE_V4;
                    let end =
                        start + (h.total_records as usize) * (RECORD_SIZE_V4_COMPACT as usize);
                    <[RangeV4Compact]>::ref_from_bytes(&self.mmap[start..end]).unwrap_or(&[])
                } else {
                    &[]
                }
            }
            HeaderVariant::V5(h) => {
                if h.is_compact_v4() {
                    let start = HEADER_SIZE_V5;
                    let end =
                        start + (h.total_records_v4 as usize) * (RECORD_SIZE_V4_COMPACT as usize);
                    <[RangeV4Compact]>::ref_from_bytes(&self.mmap[start..end]).unwrap_or(&[])
                } else {
                    &[]
                }
            }
        }
    }

    /// Zero-copy verified slice of IPv6 ranges (36 bytes per record).
    #[inline(always)]
    pub fn ranges_v6(&self) -> &[RangeV6] {
        match &self.header {
            HeaderVariant::V4(_) => &[],
            HeaderVariant::V5(h) => {
                let v4_bytes = (h.total_records_v4 as usize) * (h.record_size_v4 as usize);
                let start = HEADER_SIZE_V5 + v4_bytes;
                let end = start + (h.total_records_v6 as usize) * (RECORD_SIZE_V6 as usize);
                <[RangeV6]>::ref_from_bytes(&self.mmap[start..end]).unwrap_or(&[])
            }
        }
    }

    /// Zero-copy verified slice of normalized profiles (20 bytes per record).
    #[inline(always)]
    pub fn profiles(&self) -> &[ProfileV4] {
        let (prof_start, prof_count) = match &self.header {
            HeaderVariant::V4(h) => (h.profile_offset as usize, h.profile_count as usize),
            HeaderVariant::V5(h) => (h.profile_offset as usize, h.profile_count as usize),
        };
        let end = prof_start + prof_count * PROFILE_SIZE_V4;
        <[ProfileV4]>::ref_from_bytes(&self.mmap[prof_start..end]).unwrap_or(&[])
    }

    #[inline(always)]
    fn get_string<'a>(idx_slice: &[u8], total: usize, blob: &'a [u8], idx: usize) -> &'a str {
        if idx >= total {
            return "";
        }
        let pos = idx * 4;
        if pos + 4 > idx_slice.len() {
            return "";
        }
        let off = u32::from_le_bytes(idx_slice[pos..pos + 4].try_into().unwrap()) as usize;
        if off >= blob.len() {
            return "";
        }
        let slice = &blob[off..];
        let len = memchr::memchr(0, slice).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..len]).unwrap_or("")
    }

    #[inline(always)]
    pub fn get_city(&self, idx: usize) -> &str {
        let (count, i_start, d_start, d_len) = match &self.header {
            HeaderVariant::V4(h) => (
                h.city_count as usize,
                h.city_idx_off as usize,
                h.city_data_off as usize,
                h.city_data_len as usize,
            ),
            HeaderVariant::V5(h) => (
                h.city_count as usize,
                h.city_idx_off as usize,
                h.city_data_off as usize,
                h.city_data_len as usize,
            ),
        };
        let i_end = i_start + count * 4;
        let d_end = d_start + d_len;
        Self::get_string(
            &self.mmap[i_start..i_end],
            count,
            &self.mmap[d_start..d_end],
            idx,
        )
    }

    #[inline(always)]
    pub fn get_region(&self, idx: usize) -> &str {
        let (count, i_start, d_start, d_len) = match &self.header {
            HeaderVariant::V4(h) => (
                h.region_count as usize,
                h.region_idx_off as usize,
                h.region_data_off as usize,
                h.region_data_len as usize,
            ),
            HeaderVariant::V5(h) => (
                h.region_count as usize,
                h.region_idx_off as usize,
                h.region_data_off as usize,
                h.region_data_len as usize,
            ),
        };
        let i_end = i_start + count * 4;
        let d_end = d_start + d_len;
        Self::get_string(
            &self.mmap[i_start..i_end],
            count,
            &self.mmap[d_start..d_end],
            idx,
        )
    }

    #[inline(always)]
    pub fn get_isp(&self, idx: usize) -> &str {
        let (count, i_start, d_start, d_len) = match &self.header {
            HeaderVariant::V4(h) => (
                h.isp_count as usize,
                h.isp_idx_off as usize,
                h.isp_data_off as usize,
                h.isp_data_len as usize,
            ),
            HeaderVariant::V5(h) => (
                h.isp_count as usize,
                h.isp_idx_off as usize,
                h.isp_data_off as usize,
                h.isp_data_len as usize,
            ),
        };
        let i_end = i_start + count * 4;
        let d_end = d_start + d_len;
        Self::get_string(
            &self.mmap[i_start..i_end],
            count,
            &self.mmap[d_start..d_end],
            idx,
        )
    }

    #[inline(always)]
    fn decode_flags(&self, raw_flags: u16) -> GeoFlags {
        match &self.header {
            HeaderVariant::V4(_) => GeoFlags::from_v4(raw_flags),
            HeaderVariant::V5(_) => GeoFlags(raw_flags),
        }
    }

    /// Lookup an IPv4 integer returning a borrowed view `GeoRecordRef`.
    #[inline]
    pub fn lookup_u32(&self, ip: u32) -> Option<GeoRecordRef<'_>> {
        if self.len_v4() == 0 {
            return None;
        }

        if self.is_compact() {
            let ranges = self.ranges_compact();
            let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from) {
                Ok(i) => i,
                Err(0) => return None,
                Err(i) => i - 1,
            };
            let range = ranges.get(idx)?;
            if !range.contains(ip) {
                return None;
            }
            let profiles = self.profiles();
            let prof = profiles.get(range.profile_id as usize)?;

            Some(GeoRecordRef {
                ip: IpAddr::V4(Ipv4Addr::from(ip)),
                ip_from: range.ip_from as u128,
                ip_to: range.ip_to() as u128,
                is_v6: false,
                country: prof.country_code(),
                region: self.get_region(prof.reg_idx as usize),
                city: self.get_city(prof.city_idx as usize),
                isp: self.get_isp(prof.isp_idx as usize),
                asn: prof.asn,
                latitude: prof.latitude(),
                longitude: prof.longitude(),
                flags: self.decode_flags(prof.flags),
            })
        } else {
            let ranges = self.ranges();
            let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from) {
                Ok(i) => i,
                Err(0) => return None,
                Err(i) => i - 1,
            };
            let range = ranges.get(idx)?;
            if !range.contains(ip) {
                return None;
            }
            let profiles = self.profiles();
            let prof = profiles.get(range.profile_id as usize)?;

            Some(GeoRecordRef {
                ip: IpAddr::V4(Ipv4Addr::from(ip)),
                ip_from: range.ip_from as u128,
                ip_to: range.ip_to as u128,
                is_v6: false,
                country: prof.country_code(),
                region: self.get_region(prof.reg_idx as usize),
                city: self.get_city(prof.city_idx as usize),
                isp: self.get_isp(prof.isp_idx as usize),
                asn: prof.asn,
                latitude: prof.latitude(),
                longitude: prof.longitude(),
                flags: self.decode_flags(prof.flags),
            })
        }
    }

    /// Lookup an IPv6 128-bit integer returning a borrowed view `GeoRecordRef`.
    #[inline]
    pub fn lookup_u128(&self, ip: u128) -> Option<GeoRecordRef<'_>> {
        let ranges = self.ranges_v6();
        if ranges.is_empty() {
            return None;
        }

        let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };

        let range = ranges.get(idx)?;
        if !range.contains(ip) {
            return None;
        }

        let profiles = self.profiles();
        let prof = profiles.get(range.profile_id as usize)?;

        Some(GeoRecordRef {
            ip: IpAddr::V6(Ipv6Addr::from(ip)),
            ip_from: range.ip_from,
            ip_to: range.ip_to,
            is_v6: true,
            country: prof.country_code(),
            region: self.get_region(prof.reg_idx as usize),
            city: self.get_city(prof.city_idx as usize),
            isp: self.get_isp(prof.isp_idx as usize),
            asn: prof.asn,
            latitude: prof.latitude(),
            longitude: prof.longitude(),
            flags: self.decode_flags(prof.flags),
        })
    }

    /// Looks up any `IpAddr` (IPv4 or IPv6), returning a borrowed view `GeoRecordRef`.
    #[inline]
    pub fn lookup_addr(&self, ip: IpAddr) -> Option<GeoRecordRef<'_>> {
        match ip {
            IpAddr::V4(v4) => self.lookup_u32(u32::from(v4)),
            IpAddr::V6(v6) => {
                // Check if IPv4-mapped (::ffff:x.x.x.x) and look up in IPv4 if not in IPv6
                let ip_u128 = u128::from(v6);
                if let Some(record) = self.lookup_u128(ip_u128) {
                    Some(record)
                } else if let Some(v4) = v6.to_ipv4_mapped() {
                    self.lookup_u32(u32::from(v4))
                } else {
                    None
                }
            }
        }
    }

    /// Looks up an IP address, returning a borrowed view `GeoRecordRef`.
    #[inline(always)]
    pub fn lookup_ref(&self, ip: impl Into<IpAddr>) -> Option<GeoRecordRef<'_>> {
        self.lookup_addr(ip.into())
    }

    /// Looks up an IP address, returning an owned `GeoRecord`.
    #[inline(always)]
    pub fn lookup(&self, ip: impl Into<IpAddr>) -> Option<GeoRecord> {
        self.lookup_ref(ip).map(|r| r.to_owned())
    }

    /// Looks up an IP address string (e.g. "8.8.8.8" or "2001:4860:4860::8888").
    pub fn lookup_str(&self, ip_str: &str) -> Option<GeoRecord> {
        let ip: IpAddr = ip_str.parse().ok()?;
        self.lookup(ip)
    }
}
