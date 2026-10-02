use memmap2::Mmap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::Path;
use thiserror::Error;
use zerocopy::FromBytes;

use crate::models::{
    GeoFlags, GeoRecord, GeoRecordRef, HeaderV4, ProfileV4, RangeV4, HEADER_SIZE_V4,
    PROFILE_SIZE_V4, RECORD_SIZE_V4, VERSION_V4,
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
pub struct IpAtlasReader {
    _mmap: Mmap,
    header: HeaderV4,
    ranges: &'static [RangeV4],
    profiles: &'static [ProfileV4],
    city_idx_slice: &'static [u8],
    city_data_slice: &'static [u8],
    region_idx_slice: &'static [u8],
    region_data_slice: &'static [u8],
    isp_idx_slice: &'static [u8],
    isp_data_slice: &'static [u8],
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
    fn from_mmap(mmap: Mmap, file_len: u64) -> Result<Self, ReaderError> {
        // Read header
        let header = HeaderV4::read_from_bytes(&mmap[..HEADER_SIZE_V4])
            .map_err(|_| ReaderError::Corrupted("Failed to read V4 header bytes"))?;

        if header.magic != crate::models::MAGIC {
            return Err(ReaderError::Corrupted(
                "Invalid magic bytes (expected 'ATLS')",
            ));
        }
        if header.version != VERSION_V4 {
            return Err(ReaderError::UnsupportedVersion(header.version));
        }
        if header.record_size != RECORD_SIZE_V4 {
            return Err(ReaderError::Corrupted("Unexpected record size in header"));
        }

        header.validate(file_len).map_err(ReaderError::Corrupted)?;

        let total_records = header.total_records as usize;
        let ranges_start = HEADER_SIZE_V4;
        let ranges_end = ranges_start + total_records * (RECORD_SIZE_V4 as usize);

        let total_profiles = header.profile_count as usize;
        let prof_start = header.profile_offset as usize;
        let prof_end = prof_start + total_profiles * PROFILE_SIZE_V4;

        if ranges_end > mmap.len() || prof_end > mmap.len() {
            return Err(ReaderError::Corrupted(
                "Records or profile table exceeds file length",
            ));
        }

        // Safety: RangeV4 and ProfileV4 are #[repr(C)] Plain Old Data with FromBytes.
        // The mmap buffer is kept alive inside IpAtlasReader, so &'static references tied to _mmap are safe.
        let ranges: &'static [RangeV4] = unsafe {
            let ptr = mmap.as_ptr().add(ranges_start) as *const RangeV4;
            std::slice::from_raw_parts(ptr, total_records)
        };

        let profiles: &'static [ProfileV4] = unsafe {
            let ptr = mmap.as_ptr().add(prof_start) as *const ProfileV4;
            std::slice::from_raw_parts(ptr, total_profiles)
        };

        // Extract string indices and data blobs
        let c_i_end = header.city_idx_off as usize + (header.city_count as usize) * 4;
        let c_d_end = header.city_data_off as usize + header.city_data_len as usize;
        let r_i_end = header.region_idx_off as usize + (header.region_count as usize) * 4;
        let r_d_end = header.region_data_off as usize + header.region_data_len as usize;
        let i_i_end = header.isp_idx_off as usize + (header.isp_count as usize) * 4;
        let i_d_end = header.isp_data_off as usize + header.isp_data_len as usize;

        if c_i_end > mmap.len()
            || c_d_end > mmap.len()
            || r_i_end > mmap.len()
            || r_d_end > mmap.len()
            || i_i_end > mmap.len()
            || i_d_end > mmap.len()
        {
            return Err(ReaderError::Corrupted(
                "String blob offsets exceed file boundary",
            ));
        }

        let city_idx_slice = unsafe {
            std::slice::from_raw_parts(
                mmap.as_ptr().add(header.city_idx_off as usize),
                (header.city_count as usize) * 4,
            )
        };
        let city_data_slice = unsafe {
            std::slice::from_raw_parts(
                mmap.as_ptr().add(header.city_data_off as usize),
                header.city_data_len as usize,
            )
        };

        let region_idx_slice = unsafe {
            std::slice::from_raw_parts(
                mmap.as_ptr().add(header.region_idx_off as usize),
                (header.region_count as usize) * 4,
            )
        };
        let region_data_slice = unsafe {
            std::slice::from_raw_parts(
                mmap.as_ptr().add(header.region_data_off as usize),
                header.region_data_len as usize,
            )
        };

        let isp_idx_slice = unsafe {
            std::slice::from_raw_parts(
                mmap.as_ptr().add(header.isp_idx_off as usize),
                (header.isp_count as usize) * 4,
            )
        };
        let isp_data_slice = unsafe {
            std::slice::from_raw_parts(
                mmap.as_ptr().add(header.isp_data_off as usize),
                header.isp_data_len as usize,
            )
        };

        Ok(Self {
            _mmap: mmap,
            header,
            ranges,
            profiles,
            city_idx_slice,
            city_data_slice,
            region_idx_slice,
            region_data_slice,
            isp_idx_slice,
            isp_data_slice,
        })
    }

    /// Number of IP interval ranges stored in the database.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Returns true if the database contains zero intervals.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Database format version.
    #[inline(always)]
    pub fn version(&self) -> u16 {
        self.header.version
    }

    /// Total count of unique normalized metadata profiles.
    #[inline(always)]
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
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
        Self::get_string(
            self.city_idx_slice,
            self.header.city_count as usize,
            self.city_data_slice,
            idx,
        )
    }

    #[inline(always)]
    pub fn get_region(&self, idx: usize) -> &str {
        Self::get_string(
            self.region_idx_slice,
            self.header.region_count as usize,
            self.region_data_slice,
            idx,
        )
    }

    #[inline(always)]
    pub fn get_isp(&self, idx: usize) -> &str {
        Self::get_string(
            self.isp_idx_slice,
            self.header.isp_count as usize,
            self.isp_data_slice,
            idx,
        )
    }

    /// High-performance zero-copy IP address lookup returning borrowed record view.
    #[inline]
    pub fn lookup_u32(&self, ip: u32) -> Option<GeoRecordRef<'_>> {
        if self.ranges.is_empty() {
            return None;
        }

        // Fast monotonic binary search over ip_from
        let idx = match self.ranges.binary_search_by_key(&ip, |r| r.ip_from) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };

        let range = unsafe { self.ranges.get_unchecked(idx) };
        if !range.contains(ip) {
            return None;
        }

        let prof_id = range.profile_id as usize;
        let prof = self.profiles.get(prof_id)?;

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
