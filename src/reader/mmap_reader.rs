use memmap2::Mmap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::Path;
use thiserror::Error;
use zerocopy::FromBytes;

use crate::models::{
    GeoFlags, GeoRecord, GeoRecordRef, HeaderV4, ProfileV4, RangeV4, RangeV4Compact,
    HEADER_SIZE_V4, PROFILE_SIZE_V4, RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD,
};

#[derive(Error, Debug)]
pub enum ReaderError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database file is too small: {0} bytes (< {HEADER_SIZE_V4} bytes)")]
    FileTooSmall(u64),
    #[error("Corrupted database: {0}")]
    Corrupted(&'static str),
    #[error("Unsupported database version: {0}")]
    UnsupportedVersion(u16),
}

/// Zero-copy memory-mapped IPAtlas database reader.
/// Completely sound and safe: holds the mmap allocation and computes verified zerocopy slices on the fly.
pub struct IpAtlasReader {
    mmap: Mmap,
    header: HeaderV4,
}

impl IpAtlasReader {
    /// Opens and memory-maps an IPAtlas database from disk.
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
        let header = HeaderV4::read_from_bytes(&mmap[..HEADER_SIZE_V4])
            .map_err(|_| ReaderError::Corrupted("Failed to parse V4 header bytes"))?;

        header.validate(file_len).map_err(ReaderError::Corrupted)?;

        let reader = Self { mmap, header };

        // Pre-validate that zerocopy slice decoding succeeds
        if reader.header.is_compact() {
            let start = HEADER_SIZE_V4;
            let end =
                start + (reader.header.total_records as usize) * (RECORD_SIZE_V4_COMPACT as usize);
            <[RangeV4Compact]>::ref_from_bytes(&reader.mmap[start..end])
                .map_err(|_| ReaderError::Corrupted("Unaligned or invalid RangeV4Compact slice"))?;
        } else {
            let start = HEADER_SIZE_V4;
            let end =
                start + (reader.header.total_records as usize) * (RECORD_SIZE_V4_STANDARD as usize);
            <[RangeV4]>::ref_from_bytes(&reader.mmap[start..end])
                .map_err(|_| ReaderError::Corrupted("Unaligned or invalid RangeV4 slice"))?;
        }

        let prof_start = reader.header.profile_offset as usize;
        let prof_end = prof_start + (reader.header.profile_count as usize) * PROFILE_SIZE_V4;
        <[ProfileV4]>::ref_from_bytes(&reader.mmap[prof_start..prof_end])
            .map_err(|_| ReaderError::Corrupted("Unaligned or invalid ProfileV4 slice"))?;

        Ok(reader)
    }

    /// Number of IP interval ranges stored in the database.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.header.total_records as usize
    }

    /// Returns true if the database contains zero intervals.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.header.total_records == 0
    }

    /// Database format version (4 for Standard V4, 0x0401 for Compact V4.1).
    #[inline(always)]
    pub fn version(&self) -> u16 {
        self.header.version
    }

    /// Returns true if the database is in V4.1 Compact layout (8 bytes per range).
    #[inline(always)]
    pub fn is_compact(&self) -> bool {
        self.header.is_compact()
    }

    /// Total count of unique normalized metadata profiles.
    #[inline(always)]
    pub fn profile_count(&self) -> usize {
        self.header.profile_count as usize
    }

    /// City dictionary entry count.
    #[inline(always)]
    pub fn city_count(&self) -> usize {
        self.header.city_count as usize
    }

    /// Region dictionary entry count.
    #[inline(always)]
    pub fn region_count(&self) -> usize {
        self.header.region_count as usize
    }

    /// ISP dictionary entry count.
    #[inline(always)]
    pub fn isp_count(&self) -> usize {
        self.header.isp_count as usize
    }

    /// Zero-copy verified slice of standard V4 ranges (12 bytes per record).
    #[inline(always)]
    pub fn ranges(&self) -> &[RangeV4] {
        if self.header.is_compact() {
            &[]
        } else {
            let start = HEADER_SIZE_V4;
            let end =
                start + (self.header.total_records as usize) * (RECORD_SIZE_V4_STANDARD as usize);
            <[RangeV4]>::ref_from_bytes(&self.mmap[start..end]).unwrap_or(&[])
        }
    }

    /// Zero-copy verified slice of compact V4.1 ranges (8 bytes per record).
    #[inline(always)]
    pub fn ranges_compact(&self) -> &[RangeV4Compact] {
        if self.header.is_compact() {
            let start = HEADER_SIZE_V4;
            let end =
                start + (self.header.total_records as usize) * (RECORD_SIZE_V4_COMPACT as usize);
            <[RangeV4Compact]>::ref_from_bytes(&self.mmap[start..end]).unwrap_or(&[])
        } else {
            &[]
        }
    }

    /// Zero-copy verified slice of normalized profiles (20 bytes per record).
    #[inline(always)]
    pub fn profiles(&self) -> &[ProfileV4] {
        let start = self.header.profile_offset as usize;
        let end = start + (self.header.profile_count as usize) * PROFILE_SIZE_V4;
        <[ProfileV4]>::ref_from_bytes(&self.mmap[start..end]).unwrap_or(&[])
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
        let i_start = self.header.city_idx_off as usize;
        let i_end = i_start + (self.header.city_count as usize) * 4;
        let d_start = self.header.city_data_off as usize;
        let d_end = d_start + self.header.city_data_len as usize;
        Self::get_string(
            &self.mmap[i_start..i_end],
            self.header.city_count as usize,
            &self.mmap[d_start..d_end],
            idx,
        )
    }

    #[inline(always)]
    pub fn get_region(&self, idx: usize) -> &str {
        let i_start = self.header.region_idx_off as usize;
        let i_end = i_start + (self.header.region_count as usize) * 4;
        let d_start = self.header.region_data_off as usize;
        let d_end = d_start + self.header.region_data_len as usize;
        Self::get_string(
            &self.mmap[i_start..i_end],
            self.header.region_count as usize,
            &self.mmap[d_start..d_end],
            idx,
        )
    }

    #[inline(always)]
    pub fn get_isp(&self, idx: usize) -> &str {
        let i_start = self.header.isp_idx_off as usize;
        let i_end = i_start + (self.header.isp_count as usize) * 4;
        let d_start = self.header.isp_data_off as usize;
        let d_end = d_start + self.header.isp_data_len as usize;
        Self::get_string(
            &self.mmap[i_start..i_end],
            self.header.isp_count as usize,
            &self.mmap[d_start..d_end],
            idx,
        )
    }

    /// High-performance zero-copy IP address lookup returning borrowed record view.
    #[inline]
    pub fn lookup_u32(&self, ip: u32) -> Option<GeoRecordRef<'_>> {
        if self.header.total_records == 0 {
            return None;
        }

        if self.header.is_compact() {
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
                ip: Ipv4Addr::from(ip),
                ip_from: range.ip_from,
                ip_to: range.ip_to(),
                country: prof.country_code(),
                region: self.get_region(prof.reg_idx as usize),
                city: self.get_city(prof.city_idx as usize),
                isp: self.get_isp(prof.isp_idx as usize),
                asn: prof.asn,
                latitude: prof.latitude(),
                longitude: prof.longitude(),
                flags: GeoFlags(prof.flags),
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
                ip: Ipv4Addr::from(ip),
                ip_from: range.ip_from,
                ip_to: range.ip_to,
                country: prof.country_code(),
                region: self.get_region(prof.reg_idx as usize),
                city: self.get_city(prof.city_idx as usize),
                isp: self.get_isp(prof.isp_idx as usize),
                asn: prof.asn,
                latitude: prof.latitude(),
                longitude: prof.longitude(),
                flags: GeoFlags(prof.flags),
            })
        }
    }

    /// Looks up an IPv4 address, returning a borrowed view `GeoRecordRef`.
    #[inline(always)]
    pub fn lookup_ref(&self, ip: impl Into<Ipv4Addr>) -> Option<GeoRecordRef<'_>> {
        let ip_addr: Ipv4Addr = ip.into();
        self.lookup_u32(u32::from(ip_addr))
    }

    /// Looks up an IPv4 address, returning an owned `GeoRecord`.
    #[inline(always)]
    pub fn lookup(&self, ip: impl Into<Ipv4Addr>) -> Option<GeoRecord> {
        self.lookup_ref(ip).map(|r| r.to_owned())
    }

    /// Looks up an IPv4 address string (e.g. "8.8.8.8").
    pub fn lookup_str(&self, ip_str: &str) -> Option<GeoRecord> {
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        self.lookup(ip)
    }
}
