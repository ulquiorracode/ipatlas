use memmap2::Mmap;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use thiserror::Error;
use zerocopy::FromBytes;

use crate::models::{
    compute_crc32, GeoFlags, GeoRecord, GeoRecordRef, HeaderV4, HeaderV5, ProfileV4, RangeV4,
    RangeV4Compact, RangeV6, RecordFamily, StorageLayout, HEADER_SIZE_V4, HEADER_SIZE_V5, MAGIC,
    PROFILE_SIZE_V4, RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD, VERSION_V4_COMPACT_AOS,
    VERSION_V4_COMPACT_SOA, VERSION_V4_STANDARD, VERSION_V4_STANDARD_AOS, VERSION_V4_STANDARD_SOA,
    VERSION_V5_COMPACT_AOS, VERSION_V5_COMPACT_SOA, VERSION_V5_STANDARD, VERSION_V5_STANDARD_SOA,
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct StringTableRef {
    pub(crate) count: usize,
    pub(crate) idx_start: usize,
    pub(crate) data_start: usize,
    pub(crate) data_len: usize,
}

/// Pre-validated, branchless dispatch descriptor for IPv4 range tables and columns.
/// Evaluated strictly once during `open()` / `from_mmap()`, eliminating repeated
/// `is_soa()`, `is_compact()`, and `ref_from_bytes` validation on every query.
#[derive(Clone, Copy, Debug)]
pub(crate) enum TableDispatch {
    Empty,
    V4StandardAos {
        offset: usize,
        count: usize,
    },
    V4CompactAos {
        offset: usize,
        count: usize,
    },
    V4StandardSoa {
        ip_from_off: usize,
        ip_to_off: usize,
        prof_off: usize,
        count: usize,
    },
    V4CompactSoa {
        ip_from_off: usize,
        counts_off: usize,
        prof_off: usize,
        count: usize,
    },
    V5StandardAos {
        offset: usize,
        count: usize,
    },
    V5CompactAos {
        offset: usize,
        count: usize,
    },
    V5StandardSoa {
        ip_from_off: usize,
        ip_to_off: usize,
        prof_off: usize,
        count: usize,
    },
    V5CompactSoa {
        ip_from_off: usize,
        counts_off: usize,
        prof_off: usize,
        count: usize,
    },
}

/// Zero-copy memory-mapped IPAtlas database reader supporting Generation V4 and V5 (Dual-Stack).
/// Completely sound and safe: holds the storage allocation and pre-computes verified offsets during open.
pub struct IpAtlasReader {
    mmap: StorageBuffer,
    header: HeaderVariant,
    dispatch: TableDispatch,
    v6_start: usize,
    v6_count: usize,
    prof_start: usize,
    prof_count: usize,
    cities: StringTableRef,
    regions: StringTableRef,
    isps: StringTableRef,
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
            VERSION_V5_STANDARD
            | 0x0500
            | VERSION_V5_STANDARD_SOA
            | VERSION_V5_COMPACT_AOS
            | VERSION_V5_COMPACT_SOA => {
                if file_len < HEADER_SIZE_V5 as u64 {
                    return Err(ReaderError::FileTooSmall(file_len));
                }
                let h = HeaderV5::read_from_bytes(&mmap[..HEADER_SIZE_V5])
                    .map_err(|_| ReaderError::Corrupted("Failed to parse V5 header bytes"))?;

                if h.is_embedded_zstd() {
                    #[cfg(feature = "embedded-zstd")]
                    {
                        let decompressed_payload =
                            zstd::stream::decode_all(&mmap[HEADER_SIZE_V5..])
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
                    }
                    #[cfg(not(feature = "embedded-zstd"))]
                    {
                        return Err(ReaderError::Decompression(
                            "rebuild with embedded-zstd".to_string(),
                        ));
                    }
                } else {
                    h.validate(file_len).map_err(ReaderError::Corrupted)?;
                    (HeaderVariant::V5(h), StorageBuffer::Mmap(mmap))
                }
            }
            VERSION_V4_STANDARD
            | VERSION_V4_STANDARD_AOS
            | VERSION_V4_STANDARD_SOA
            | VERSION_V4_COMPACT_AOS
            | VERSION_V4_COMPACT_SOA => {
                let h = HeaderV4::read_from_bytes(&mmap[..HEADER_SIZE_V4])
                    .map_err(|_| ReaderError::Corrupted("Failed to parse V4 header bytes"))?;
                h.validate(file_len).map_err(ReaderError::Corrupted)?;
                (HeaderVariant::V4(h), StorageBuffer::Mmap(mmap))
            }
            other => return Err(ReaderError::UnsupportedVersion(other)),
        };

        let raw_buf = &storage[..];

        // Pre-validate slices and construct TableDispatch
        let (dispatch, v6_start, v6_count, prof_start, prof_count, cities, regions, isps) =
            match &header {
                HeaderVariant::V4(h) => {
                    let total = h.total_records as usize;
                    let disp = if total == 0 {
                        TableDispatch::Empty
                    } else if h.is_soa() {
                        let start = HEADER_SIZE_V4;
                        let ip_from_bytes = total * 4;
                        <[u32]>::ref_from_bytes(&raw_buf[start..start + ip_from_bytes]).map_err(
                            |_| ReaderError::Corrupted("Unaligned or invalid SoA ip_from slice"),
                        )?;
                        if h.is_compact() {
                            let counts_start = start + ip_from_bytes;
                            let counts_bytes = total * 2;
                            let prof_start = counts_start + counts_bytes;
                            let prof_bytes = total * 2;
                            <[u16]>::ref_from_bytes(
                                &raw_buf[counts_start..counts_start + counts_bytes],
                            )
                            .map_err(|_| {
                                ReaderError::Corrupted("Unaligned or invalid SoA count slice")
                            })?;
                            <[u16]>::ref_from_bytes(&raw_buf[prof_start..prof_start + prof_bytes])
                                .map_err(|_| {
                                    ReaderError::Corrupted(
                                        "Unaligned or invalid SoA profile_id slice",
                                    )
                                })?;
                            TableDispatch::V4CompactSoa {
                                ip_from_off: start,
                                counts_off: counts_start,
                                prof_off: prof_start,
                                count: total,
                            }
                        } else {
                            let to_start = start + ip_from_bytes;
                            let to_bytes = total * 4;
                            let prof_start = to_start + to_bytes;
                            let prof_bytes = total * 4;
                            <[u32]>::ref_from_bytes(&raw_buf[to_start..to_start + to_bytes])
                                .map_err(|_| {
                                    ReaderError::Corrupted("Unaligned or invalid SoA ip_to slice")
                                })?;
                            <[u32]>::ref_from_bytes(&raw_buf[prof_start..prof_start + prof_bytes])
                                .map_err(|_| {
                                    ReaderError::Corrupted(
                                        "Unaligned or invalid SoA profile_id slice",
                                    )
                                })?;
                            TableDispatch::V4StandardSoa {
                                ip_from_off: start,
                                ip_to_off: to_start,
                                prof_off: prof_start,
                                count: total,
                            }
                        }
                    } else if h.is_compact() {
                        let start = HEADER_SIZE_V4;
                        let end = start + total * (RECORD_SIZE_V4_COMPACT as usize);
                        <[RangeV4Compact]>::ref_from_bytes(&raw_buf[start..end]).map_err(|_| {
                            ReaderError::Corrupted("Unaligned or invalid RangeV4Compact slice")
                        })?;
                        TableDispatch::V4CompactAos {
                            offset: start,
                            count: total,
                        }
                    } else {
                        let start = HEADER_SIZE_V4;
                        let end = start + total * (RECORD_SIZE_V4_STANDARD as usize);
                        <[RangeV4]>::ref_from_bytes(&raw_buf[start..end]).map_err(|_| {
                            ReaderError::Corrupted("Unaligned or invalid RangeV4 slice")
                        })?;
                        TableDispatch::V4StandardAos {
                            offset: start,
                            count: total,
                        }
                    };

                    let p_start = h.profile_offset as usize;
                    let p_count = h.profile_count as usize;
                    let p_end = p_start + p_count * PROFILE_SIZE_V4;
                    <[ProfileV4]>::ref_from_bytes(&raw_buf[p_start..p_end]).map_err(|_| {
                        ReaderError::Corrupted("Unaligned or invalid ProfileV4 slice")
                    })?;

                    let c_ref = StringTableRef {
                        count: h.city_count as usize,
                        idx_start: h.city_idx_off as usize,
                        data_start: h.city_data_off as usize,
                        data_len: h.city_data_len as usize,
                    };
                    let r_ref = StringTableRef {
                        count: h.region_count as usize,
                        idx_start: h.region_idx_off as usize,
                        data_start: h.region_data_off as usize,
                        data_len: h.region_data_len as usize,
                    };
                    let i_ref = StringTableRef {
                        count: h.isp_count as usize,
                        idx_start: h.isp_idx_off as usize,
                        data_start: h.isp_data_off as usize,
                        data_len: h.isp_data_len as usize,
                    };

                    (disp, 0, 0, p_start, p_count, c_ref, r_ref, i_ref)
                }
                HeaderVariant::V5(h) => {
                    let total_v4 = h.total_records_v4 as usize;
                    let v4_start = HEADER_SIZE_V5;
                    let v4_end = v4_start + total_v4 * (h.record_size_v4 as usize);

                    let disp = if total_v4 == 0 {
                        TableDispatch::Empty
                    } else if h.is_soa() {
                        let ip_from_bytes = total_v4 * 4;
                        <[u32]>::ref_from_bytes(&raw_buf[v4_start..v4_start + ip_from_bytes])
                            .map_err(|_| {
                                ReaderError::Corrupted("Unaligned or invalid SoA ip_from slice")
                            })?;
                        if h.is_compact_v4() {
                            let counts_start = v4_start + ip_from_bytes;
                            let counts_bytes = total_v4 * 2;
                            let prof_start = counts_start + counts_bytes;
                            let prof_bytes = total_v4 * 2;
                            <[u16]>::ref_from_bytes(
                                &raw_buf[counts_start..counts_start + counts_bytes],
                            )
                            .map_err(|_| {
                                ReaderError::Corrupted("Unaligned or invalid SoA count slice")
                            })?;
                            <[u16]>::ref_from_bytes(&raw_buf[prof_start..prof_start + prof_bytes])
                                .map_err(|_| {
                                    ReaderError::Corrupted(
                                        "Unaligned or invalid SoA profile_id slice",
                                    )
                                })?;
                            TableDispatch::V5CompactSoa {
                                ip_from_off: v4_start,
                                counts_off: counts_start,
                                prof_off: prof_start,
                                count: total_v4,
                            }
                        } else {
                            let to_start = v4_start + ip_from_bytes;
                            let to_bytes = total_v4 * 4;
                            let prof_start = to_start + to_bytes;
                            let prof_bytes = total_v4 * 4;
                            <[u32]>::ref_from_bytes(&raw_buf[to_start..to_start + to_bytes])
                                .map_err(|_| {
                                    ReaderError::Corrupted("Unaligned or invalid SoA ip_to slice")
                                })?;
                            <[u32]>::ref_from_bytes(&raw_buf[prof_start..prof_start + prof_bytes])
                                .map_err(|_| {
                                    ReaderError::Corrupted(
                                        "Unaligned or invalid SoA profile_id slice",
                                    )
                                })?;
                            TableDispatch::V5StandardSoa {
                                ip_from_off: v4_start,
                                ip_to_off: to_start,
                                prof_off: prof_start,
                                count: total_v4,
                            }
                        }
                    } else if h.is_compact_v4() {
                        <[RangeV4Compact]>::ref_from_bytes(&raw_buf[v4_start..v4_end]).map_err(
                            |_| ReaderError::Corrupted("Unaligned or invalid RangeV4Compact slice"),
                        )?;
                        TableDispatch::V5CompactAos {
                            offset: v4_start,
                            count: total_v4,
                        }
                    } else {
                        <[RangeV4]>::ref_from_bytes(&raw_buf[v4_start..v4_end]).map_err(|_| {
                            ReaderError::Corrupted("Unaligned or invalid RangeV4 slice")
                        })?;
                        TableDispatch::V5StandardAos {
                            offset: v4_start,
                            count: total_v4,
                        }
                    };

                    let total_v6 = h.total_records_v6 as usize;
                    let v6_start = v4_end;
                    let v6_end = v6_start + total_v6 * (h.record_size_v6 as usize);
                    if total_v6 > 0 {
                        <[RangeV6]>::ref_from_bytes(&raw_buf[v6_start..v6_end]).map_err(|_| {
                            ReaderError::Corrupted("Unaligned or invalid RangeV6 slice")
                        })?;
                    }

                    let p_start = h.profile_offset as usize;
                    let p_count = h.profile_count as usize;
                    let p_end = p_start + p_count * PROFILE_SIZE_V4;
                    <[ProfileV4]>::ref_from_bytes(&raw_buf[p_start..p_end]).map_err(|_| {
                        ReaderError::Corrupted("Unaligned or invalid ProfileV4 slice")
                    })?;

                    let c_ref = StringTableRef {
                        count: h.city_count as usize,
                        idx_start: h.city_idx_off as usize,
                        data_start: h.city_data_off as usize,
                        data_len: h.city_data_len as usize,
                    };
                    let r_ref = StringTableRef {
                        count: h.region_count as usize,
                        idx_start: h.region_idx_off as usize,
                        data_start: h.region_data_off as usize,
                        data_len: h.region_data_len as usize,
                    };
                    let i_ref = StringTableRef {
                        count: h.isp_count as usize,
                        idx_start: h.isp_idx_off as usize,
                        data_start: h.isp_data_off as usize,
                        data_len: h.isp_data_len as usize,
                    };

                    (
                        disp, v6_start, total_v6, p_start, p_count, c_ref, r_ref, i_ref,
                    )
                }
            };

        let reader = Self {
            mmap: storage,
            header,
            dispatch,
            v6_start,
            v6_count,
            prof_start,
            prof_count,
            cities,
            regions,
            isps,
        };

        #[cfg(unix)]
        {
            if let StorageBuffer::Mmap(ref m) = reader.mmap {
                // SAFETY: mmap is valid and mapped, advises kernel for binary search access pattern.
                unsafe {
                    libc::madvise(m.as_ptr() as *mut libc::c_void, m.len(), libc::MADV_RANDOM);
                }
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

    /// Returns true if the database is in Structure of Arrays (SoA) layout.
    #[inline(always)]
    pub fn is_soa(&self) -> bool {
        match &self.header {
            HeaderVariant::V4(h) => h.is_soa(),
            HeaderVariant::V5(h) => h.is_soa(),
        }
    }

    /// Physical memory layout.
    #[inline(always)]
    pub fn layout(&self) -> StorageLayout {
        if self.is_soa() {
            StorageLayout::Soa
        } else {
            StorageLayout::Aos
        }
    }

    /// Record family.
    #[inline(always)]
    pub fn family(&self) -> RecordFamily {
        if self.is_compact() {
            RecordFamily::Compact
        } else {
            RecordFamily::Standard
        }
    }

    /// Zero-copy verified slice of SoA IPv4 starting addresses (`ip_from`).
    #[inline(always)]
    pub fn soa_ip_froms_v4(&self) -> &[u32] {
        match self.dispatch {
            TableDispatch::V4StandardSoa {
                ip_from_off, count, ..
            }
            | TableDispatch::V4CompactSoa {
                ip_from_off, count, ..
            }
            | TableDispatch::V5StandardSoa {
                ip_from_off, count, ..
            }
            | TableDispatch::V5CompactSoa {
                ip_from_off, count, ..
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_from_off) as *const u32,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of SoA Compact IPv4 interval counts (`u16`).
    #[inline(always)]
    pub fn soa_counts_v4(&self) -> &[u16] {
        match self.dispatch {
            TableDispatch::V4CompactSoa {
                counts_off, count, ..
            }
            | TableDispatch::V5CompactSoa {
                counts_off, count, ..
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(counts_off) as *const u16,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of SoA Compact IPv4 profile IDs (`u16`).
    #[inline(always)]
    pub fn soa_profile_ids_compact_v4(&self) -> &[u16] {
        match self.dispatch {
            TableDispatch::V4CompactSoa {
                prof_off, count, ..
            }
            | TableDispatch::V5CompactSoa {
                prof_off, count, ..
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(prof_off) as *const u16,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of SoA Standard IPv4 ending addresses (`ip_to`, `u32`).
    #[inline(always)]
    pub fn soa_ip_tos_standard_v4(&self) -> &[u32] {
        match self.dispatch {
            TableDispatch::V4StandardSoa {
                ip_to_off, count, ..
            }
            | TableDispatch::V5StandardSoa {
                ip_to_off, count, ..
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_to_off) as *const u32,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of SoA Standard IPv4 profile IDs (`u32`).
    #[inline(always)]
    pub fn soa_profile_ids_standard_v4(&self) -> &[u32] {
        match self.dispatch {
            TableDispatch::V4StandardSoa {
                prof_off, count, ..
            }
            | TableDispatch::V5StandardSoa {
                prof_off, count, ..
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(prof_off) as *const u32,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of standard V4 ranges (12 bytes per record).
    #[inline(always)]
    pub fn ranges(&self) -> &[RangeV4] {
        match self.dispatch {
            TableDispatch::V4StandardAos { offset, count }
            | TableDispatch::V5StandardAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const RangeV4,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of compact V4 ranges (8 bytes per record).
    #[inline(always)]
    pub fn ranges_compact(&self) -> &[RangeV4Compact] {
        match self.dispatch {
            TableDispatch::V4CompactAos { offset, count }
            | TableDispatch::V5CompactAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const RangeV4Compact,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of IPv6 ranges (36 bytes per record).
    #[inline(always)]
    pub fn ranges_v6(&self) -> &[RangeV6] {
        if self.v6_count == 0 {
            return &[];
        }
        // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
        unsafe {
            std::slice::from_raw_parts(
                self.mmap.as_ptr().add(self.v6_start) as *const RangeV6,
                self.v6_count,
            )
        }
    }

    /// Zero-copy verified slice of normalized profiles (20 bytes per record).
    #[inline(always)]
    pub fn profiles(&self) -> &[ProfileV4] {
        if self.prof_count == 0 {
            return &[];
        }
        // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
        unsafe {
            std::slice::from_raw_parts(
                self.mmap.as_ptr().add(self.prof_start) as *const ProfileV4,
                self.prof_count,
            )
        }
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
        let i_end = self.cities.idx_start + self.cities.count * 4;
        let d_end = self.cities.data_start + self.cities.data_len;
        Self::get_string(
            &self.mmap[self.cities.idx_start..i_end],
            self.cities.count,
            &self.mmap[self.cities.data_start..d_end],
            idx,
        )
    }

    #[inline(always)]
    pub fn get_region(&self, idx: usize) -> &str {
        let i_end = self.regions.idx_start + self.regions.count * 4;
        let d_end = self.regions.data_start + self.regions.data_len;
        Self::get_string(
            &self.mmap[self.regions.idx_start..i_end],
            self.regions.count,
            &self.mmap[self.regions.data_start..d_end],
            idx,
        )
    }

    #[inline(always)]
    pub fn get_isp(&self, idx: usize) -> &str {
        let i_end = self.isps.idx_start + self.isps.count * 4;
        let d_end = self.isps.data_start + self.isps.data_len;
        Self::get_string(
            &self.mmap[self.isps.idx_start..i_end],
            self.isps.count,
            &self.mmap[self.isps.data_start..d_end],
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
        let (ip_from, ip_to, profile_id) = match self.dispatch {
            TableDispatch::V4StandardSoa {
                ip_from_off,
                ip_to_off,
                prof_off,
                count,
            }
            | TableDispatch::V5StandardSoa {
                ip_from_off,
                ip_to_off,
                prof_off,
                count,
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ip_froms: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_from_off) as *const u32,
                        count,
                    )
                };
                let idx = match ip_froms.binary_search(&ip) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let ip_from = ip_froms[idx];
                let tos: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_to_off) as *const u32,
                        count,
                    )
                };
                let to = *tos.get(idx)?;
                if ip > to {
                    return None;
                }
                let prof_ids: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(prof_off) as *const u32,
                        count,
                    )
                };
                (ip_from, to, *prof_ids.get(idx)? as usize)
            }
            TableDispatch::V4CompactSoa {
                ip_from_off,
                counts_off,
                prof_off,
                count,
            }
            | TableDispatch::V5CompactSoa {
                ip_from_off,
                counts_off,
                prof_off,
                count,
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ip_froms: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_from_off) as *const u32,
                        count,
                    )
                };
                let idx = match ip_froms.binary_search(&ip) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let ip_from = ip_froms[idx];
                let counts: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(counts_off) as *const u16,
                        count,
                    )
                };
                let c = *counts.get(idx)?;
                let to = ip_from.saturating_add(c as u32);
                if ip > to {
                    return None;
                }
                let prof_ids: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(prof_off) as *const u16,
                        count,
                    )
                };
                (ip_from, to, *prof_ids.get(idx)? as usize)
            }
            TableDispatch::V4CompactAos { offset, count }
            | TableDispatch::V5CompactAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[RangeV4Compact] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const RangeV4Compact,
                        count,
                    )
                };
                let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                (range.ip_from, range.ip_to(), range.profile_id as usize)
            }
            TableDispatch::V4StandardAos { offset, count }
            | TableDispatch::V5StandardAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[RangeV4] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const RangeV4,
                        count,
                    )
                };
                let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                (range.ip_from, range.ip_to, range.profile_id as usize)
            }
            TableDispatch::Empty => return None,
        };

        let profiles = self.profiles();
        let prof = profiles.get(profile_id)?;

        Some(GeoRecordRef {
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            ip_from: ip_from as u128,
            ip_to: ip_to as u128,
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

    /// Advises the OS kernel to prefetch memory pages into RAM via `madvise(MADV_WILLNEED)` on Unix systems.
    pub fn warmup(&self) {
        #[cfg(unix)]
        {
            if let StorageBuffer::Mmap(ref m) = self.mmap {
                // SAFETY: mmap is valid and mapped, passes valid pointer and length to madvise.
                unsafe {
                    libc::madvise(
                        m.as_ptr() as *mut libc::c_void,
                        m.len(),
                        libc::MADV_WILLNEED,
                    );
                }
            }
        }
        // Force paging of ranges and profile tables
        if self.is_soa() {
            let ip_froms = self.soa_ip_froms_v4();
            if !ip_froms.is_empty() {
                let _ = std::hint::black_box(ip_froms[0]);
                let _ = std::hint::black_box(ip_froms[ip_froms.len() / 2]);
                let _ = std::hint::black_box(ip_froms[ip_froms.len() - 1]);
            }
        } else if self.is_compact() {
            let ranges = self.ranges_compact();
            if !ranges.is_empty() {
                let _ = std::hint::black_box(ranges[0].ip_from);
                let _ = std::hint::black_box(ranges[ranges.len() / 2].ip_from);
                let _ = std::hint::black_box(ranges[ranges.len() - 1].ip_from);
            }
        } else {
            let ranges = self.ranges();
            if !ranges.is_empty() {
                let _ = std::hint::black_box(ranges[0].ip_from);
                let _ = std::hint::black_box(ranges[ranges.len() / 2].ip_from);
                let _ = std::hint::black_box(ranges[ranges.len() - 1].ip_from);
            }
        }
        let profiles = self.profiles();
        if !profiles.is_empty() {
            let _ = std::hint::black_box(profiles[0].flags);
            let _ = std::hint::black_box(profiles[profiles.len() - 1].flags);
        }
    }

    /// Fast-path lookup returning only threat/usage flags for an IPv4 address.
    /// Performs zero string resolution (`memchr`) and zero UTF-8 validation.
    #[inline]
    pub fn lookup_flags_u32(&self, ip: u32) -> Option<GeoFlags> {
        let profile_id = match self.dispatch {
            TableDispatch::V4StandardSoa {
                ip_from_off,
                ip_to_off,
                prof_off,
                count,
            }
            | TableDispatch::V5StandardSoa {
                ip_from_off,
                ip_to_off,
                prof_off,
                count,
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ip_froms: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_from_off) as *const u32,
                        count,
                    )
                };
                let idx = match ip_froms.binary_search(&ip) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let tos: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_to_off) as *const u32,
                        count,
                    )
                };
                if ip > *tos.get(idx)? {
                    return None;
                }
                let prof_ids: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(prof_off) as *const u32,
                        count,
                    )
                };
                *prof_ids.get(idx)? as usize
            }
            TableDispatch::V4CompactSoa {
                ip_from_off,
                counts_off,
                prof_off,
                count,
            }
            | TableDispatch::V5CompactSoa {
                ip_from_off,
                counts_off,
                prof_off,
                count,
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ip_froms: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_from_off) as *const u32,
                        count,
                    )
                };
                let idx = match ip_froms.binary_search(&ip) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let ip_from = ip_froms[idx];
                let counts: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(counts_off) as *const u16,
                        count,
                    )
                };
                let count_val = *counts.get(idx)?;
                if ip > ip_from.saturating_add(count_val as u32) {
                    return None;
                }
                let prof_ids: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(prof_off) as *const u16,
                        count,
                    )
                };
                *prof_ids.get(idx)? as usize
            }
            TableDispatch::V4CompactAos { offset, count }
            | TableDispatch::V5CompactAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[RangeV4Compact] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const RangeV4Compact,
                        count,
                    )
                };
                let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                range.profile_id as usize
            }
            TableDispatch::V4StandardAos { offset, count }
            | TableDispatch::V5StandardAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[RangeV4] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const RangeV4,
                        count,
                    )
                };
                let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                range.profile_id as usize
            }
            TableDispatch::Empty => return None,
        };

        let profiles = self.profiles();
        let prof = profiles.get(profile_id)?;
        Some(self.decode_flags(prof.flags))
    }

    /// Fast-path lookup returning only threat/usage flags for an IPv6 address.
    #[inline]
    pub fn lookup_flags_u128(&self, ip: u128) -> Option<GeoFlags> {
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
        Some(self.decode_flags(prof.flags))
    }

    /// Fast-path lookup returning only threat/usage flags for an `IpAddr`.
    #[inline]
    pub fn lookup_flags_addr(&self, ip: IpAddr) -> Option<GeoFlags> {
        match ip {
            IpAddr::V4(v4) => self.lookup_flags_u32(u32::from(v4)),
            IpAddr::V6(v6) => {
                let ip_u128 = u128::from(v6);
                if let Some(flags) = self.lookup_flags_u128(ip_u128) {
                    Some(flags)
                } else if let Some(v4) = v6.to_ipv4_mapped() {
                    self.lookup_flags_u32(u32::from(v4))
                } else {
                    None
                }
            }
        }
    }

    /// Fast-path lookup returning only threat/usage flags for an IP address.
    #[inline(always)]
    pub fn lookup_flags(&self, ip: impl Into<IpAddr>) -> Option<GeoFlags> {
        self.lookup_flags_addr(ip.into())
    }

    /// Returns ISO 2-letter country code directly without resolving city, region, or ISP strings.
    #[inline]
    pub fn lookup_country_code_u32(&self, ip: u32) -> Option<&str> {
        let profile_id = match self.dispatch {
            TableDispatch::V4StandardSoa {
                ip_from_off,
                ip_to_off,
                prof_off,
                count,
            }
            | TableDispatch::V5StandardSoa {
                ip_from_off,
                ip_to_off,
                prof_off,
                count,
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ip_froms: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_from_off) as *const u32,
                        count,
                    )
                };
                let idx = match ip_froms.binary_search(&ip) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let tos: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_to_off) as *const u32,
                        count,
                    )
                };
                if ip > *tos.get(idx)? {
                    return None;
                }
                let prof_ids: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(prof_off) as *const u32,
                        count,
                    )
                };
                *prof_ids.get(idx)? as usize
            }
            TableDispatch::V4CompactSoa {
                ip_from_off,
                counts_off,
                prof_off,
                count,
            }
            | TableDispatch::V5CompactSoa {
                ip_from_off,
                counts_off,
                prof_off,
                count,
            } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ip_froms: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(ip_from_off) as *const u32,
                        count,
                    )
                };
                let idx = match ip_froms.binary_search(&ip) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let ip_from = ip_froms[idx];
                let counts: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(counts_off) as *const u16,
                        count,
                    )
                };
                let count_val = *counts.get(idx)?;
                if ip > ip_from.saturating_add(count_val as u32) {
                    return None;
                }
                let prof_ids: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(prof_off) as *const u16,
                        count,
                    )
                };
                *prof_ids.get(idx)? as usize
            }
            TableDispatch::V4CompactAos { offset, count }
            | TableDispatch::V5CompactAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[RangeV4Compact] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const RangeV4Compact,
                        count,
                    )
                };
                let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                range.profile_id as usize
            }
            TableDispatch::V4StandardAos { offset, count }
            | TableDispatch::V5StandardAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[RangeV4] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const RangeV4,
                        count,
                    )
                };
                let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                range.profile_id as usize
            }
            TableDispatch::Empty => return None,
        };

        let profiles = self.profiles();
        profiles.get(profile_id).map(|p| p.country_code())
    }

    /// Fast-path boolean predicate: returns true if the IPv4 is a known threat (Proxy, VPN, Tor, Botnet, Spam).
    #[inline(always)]
    pub fn is_threat_u32(&self, ip: u32) -> bool {
        self.lookup_flags_u32(ip).is_some_and(|f| f.is_threat())
    }

    /// Fast-path boolean predicate: returns true if the IP is a known threat.
    #[inline(always)]
    pub fn is_threat(&self, ip: impl Into<IpAddr>) -> bool {
        self.lookup_flags(ip).is_some_and(|f| f.is_threat())
    }

    /// Fast-path boolean predicate: returns true if the IPv4 is a proxy, VPN, or Tor node.
    #[inline(always)]
    pub fn is_proxy_u32(&self, ip: u32) -> bool {
        self.lookup_flags_u32(ip).is_some_and(|f| f.is_proxy())
    }

    /// Fast-path boolean predicate: returns true if the IP is a proxy, VPN, or Tor node.
    #[inline(always)]
    pub fn is_proxy(&self, ip: impl Into<IpAddr>) -> bool {
        self.lookup_flags(ip).is_some_and(|f| f.is_proxy())
    }

    /// Fast-path boolean predicate: returns true if the IPv4 belongs to a datacenter / cloud provider.
    #[inline(always)]
    pub fn is_datacenter_u32(&self, ip: u32) -> bool {
        self.lookup_flags_u32(ip).is_some_and(|f| f.is_datacenter())
    }

    /// Fast-path boolean predicate: returns true if the IP belongs to a datacenter / cloud provider.
    #[inline(always)]
    pub fn is_datacenter(&self, ip: impl Into<IpAddr>) -> bool {
        self.lookup_flags(ip).is_some_and(|f| f.is_datacenter())
    }
}
