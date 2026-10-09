use memmap2::Mmap;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use zerocopy::FromBytes;

use crate::models::{
    compute_crc32, GeoFlags, GeoRecord, GeoRecordRef, HeaderV4, HeaderV5, Ipv4Range,
    Ipv4RangeCompact, Ipv6Range, Ipv6RangeSplit64, ProfileGen4, RecordFamily, StorageLayout,
    HEADER_SIZE_V4, HEADER_SIZE_V5, MAGIC, PROFILE_SIZE_V4, RECORD_SIZE_V4_COMPACT,
    RECORD_SIZE_V4_STANDARD, VERSION_V4_COMPACT_AOS, VERSION_V4_COMPACT_SOA, VERSION_V4_STANDARD,
    VERSION_V4_STANDARD_AOS, VERSION_V4_STANDARD_SOA, VERSION_V5_COMPACT_AOS,
    VERSION_V5_COMPACT_SOA, VERSION_V5_STANDARD, VERSION_V5_STANDARD_SOA,
};
pub use crate::reader::buffer::StorageBuffer;
pub(crate) use crate::reader::dispatch::{TableDispatch, TableDispatchV6};
pub use crate::reader::error::ReaderError;
pub(crate) use crate::reader::strings::StringTableRef;

#[derive(Clone, Copy, Debug)]
pub enum HeaderVariant {
    V4(HeaderV4),
    V5(HeaderV5),
}

/// Zero-copy memory-mapped IPAtlas database reader supporting Generation V4 and V5 (Dual-Stack).
/// Completely sound and safe: holds the storage allocation and pre-computes verified offsets during open.
pub struct IpAtlasReader {
    mmap: StorageBuffer,
    header: HeaderVariant,
    dispatch: TableDispatch,
    dispatch_v6: TableDispatchV6,
    prof_start: usize,
    prof_count: usize,
    cities: StringTableRef,
    regions: StringTableRef,
    isps: StringTableRef,
}

impl std::fmt::Debug for IpAtlasReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpAtlasReader")
            .field("header", &self.header)
            .field("prof_count", &self.prof_count)
            .finish_non_exhaustive()
    }
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

    /// Opens and verifies CRC32 (V5 only; V4 no-op). `open()` stays header-only.
    pub fn open_verified<P: AsRef<Path>>(path: P) -> Result<Self, ReaderError> {
        let reader = Self::open(path)?;
        reader.validate_checksum()?;
        Ok(reader)
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
        let (dispatch, dispatch_v6, prof_start, prof_count, cities, regions, isps) = match &header {
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
                                ReaderError::Corrupted("Unaligned or invalid SoA profile_id slice")
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
                        <[u32]>::ref_from_bytes(&raw_buf[to_start..to_start + to_bytes]).map_err(
                            |_| ReaderError::Corrupted("Unaligned or invalid SoA ip_to slice"),
                        )?;
                        <[u32]>::ref_from_bytes(&raw_buf[prof_start..prof_start + prof_bytes])
                            .map_err(|_| {
                                ReaderError::Corrupted("Unaligned or invalid SoA profile_id slice")
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
                    <[Ipv4RangeCompact]>::ref_from_bytes(&raw_buf[start..end]).map_err(|_| {
                        ReaderError::Corrupted("Unaligned or invalid Ipv4RangeCompact slice")
                    })?;
                    TableDispatch::V4CompactAos {
                        offset: start,
                        count: total,
                    }
                } else {
                    let start = HEADER_SIZE_V4;
                    let end = start + total * (RECORD_SIZE_V4_STANDARD as usize);
                    <[Ipv4Range]>::ref_from_bytes(&raw_buf[start..end]).map_err(|_| {
                        ReaderError::Corrupted("Unaligned or invalid Ipv4Range slice")
                    })?;
                    TableDispatch::V4StandardAos {
                        offset: start,
                        count: total,
                    }
                };

                let p_start = h.profile_offset as usize;
                let p_count = h.profile_count as usize;
                let p_end = p_start + p_count * PROFILE_SIZE_V4;
                <[ProfileGen4]>::ref_from_bytes(&raw_buf[p_start..p_end]).map_err(|_| {
                    ReaderError::Corrupted("Unaligned or invalid ProfileGen4 slice")
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
                    disp,
                    TableDispatchV6::Empty,
                    p_start,
                    p_count,
                    c_ref,
                    r_ref,
                    i_ref,
                )
            }
            HeaderVariant::V5(h) => {
                let total_v4 = h.total_records_v4 as usize;
                let v4_start = HEADER_SIZE_V5;
                let v4_end = v4_start + total_v4 * (h.record_size_v4 as usize);

                let disp = if total_v4 == 0 {
                    TableDispatch::Empty
                } else if h.is_soa() {
                    let ip_from_bytes = total_v4 * 4;
                    <[u32]>::ref_from_bytes(&raw_buf[v4_start..v4_start + ip_from_bytes]).map_err(
                        |_| ReaderError::Corrupted("Unaligned or invalid SoA ip_from slice"),
                    )?;
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
                                ReaderError::Corrupted("Unaligned or invalid SoA profile_id slice")
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
                        <[u32]>::ref_from_bytes(&raw_buf[to_start..to_start + to_bytes]).map_err(
                            |_| ReaderError::Corrupted("Unaligned or invalid SoA ip_to slice"),
                        )?;
                        <[u32]>::ref_from_bytes(&raw_buf[prof_start..prof_start + prof_bytes])
                            .map_err(|_| {
                                ReaderError::Corrupted("Unaligned or invalid SoA profile_id slice")
                            })?;
                        TableDispatch::V5StandardSoa {
                            ip_from_off: v4_start,
                            ip_to_off: to_start,
                            prof_off: prof_start,
                            count: total_v4,
                        }
                    }
                } else if h.is_compact_v4() {
                    <[Ipv4RangeCompact]>::ref_from_bytes(&raw_buf[v4_start..v4_end]).map_err(
                        |_| ReaderError::Corrupted("Unaligned or invalid Ipv4RangeCompact slice"),
                    )?;
                    TableDispatch::V5CompactAos {
                        offset: v4_start,
                        count: total_v4,
                    }
                } else {
                    <[Ipv4Range]>::ref_from_bytes(&raw_buf[v4_start..v4_end]).map_err(|_| {
                        ReaderError::Corrupted("Unaligned or invalid Ipv4Range slice")
                    })?;
                    TableDispatch::V5StandardAos {
                        offset: v4_start,
                        count: total_v4,
                    }
                };

                let total_v6 = h.total_records_v6 as usize;
                let v6_start = v4_end;
                let v6_end = v6_start + total_v6 * (h.record_size_v6 as usize);
                let disp_v6 = if total_v6 == 0 {
                    TableDispatchV6::Empty
                } else if h.is_compact_v6() {
                    <[Ipv6RangeSplit64]>::ref_from_bytes(&raw_buf[v6_start..v6_end]).map_err(
                        |_| ReaderError::Corrupted("Unaligned or invalid Ipv6RangeSplit64 slice"),
                    )?;
                    TableDispatchV6::Split64Compact {
                        offset: v6_start,
                        count: total_v6,
                    }
                } else {
                    <[Ipv6Range]>::ref_from_bytes(&raw_buf[v6_start..v6_end]).map_err(|_| {
                        ReaderError::Corrupted("Unaligned or invalid Ipv6Range slice")
                    })?;
                    TableDispatchV6::StandardAos {
                        offset: v6_start,
                        count: total_v6,
                    }
                };

                let p_start = h.profile_offset as usize;
                let p_count = h.profile_count as usize;
                let p_end = p_start + p_count * PROFILE_SIZE_V4;
                <[ProfileGen4]>::ref_from_bytes(&raw_buf[p_start..p_end]).map_err(|_| {
                    ReaderError::Corrupted("Unaligned or invalid ProfileGen4 slice")
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

                (disp, disp_v6, p_start, p_count, c_ref, r_ref, i_ref)
            }
        };

        let reader = Self {
            mmap: storage,
            header,
            dispatch,
            dispatch_v6,
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

    /// Returns the underlying database header variant.
    #[inline(always)]
    pub fn header(&self) -> HeaderVariant {
        self.header
    }

    /// Returns the raw memory-mapped buffer of the database.
    #[inline(always)]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.mmap
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

    /// Zero-copy verified slice of standard IPv4 ranges (12 bytes per record).
    #[inline(always)]
    pub fn ranges_ipv4(&self) -> &[Ipv4Range] {
        match self.dispatch {
            TableDispatch::V4StandardAos { offset, count }
            | TableDispatch::V5StandardAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const Ipv4Range,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of compact IPv4 ranges (8 bytes per record).
    #[inline(always)]
    pub fn ranges_ipv4_compact(&self) -> &[Ipv4RangeCompact] {
        match self.dispatch {
            TableDispatch::V4CompactAos { offset, count }
            | TableDispatch::V5CompactAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const Ipv4RangeCompact,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of Standard IPv6 ranges (36 bytes per record).
    #[inline(always)]
    pub fn ranges_ipv6(&self) -> &[Ipv6Range] {
        match self.dispatch_v6 {
            TableDispatchV6::StandardAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const Ipv6Range,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Zero-copy verified slice of Compact IPv6 Split-64 ranges (16 bytes per record).
    #[inline(always)]
    pub fn ranges_ipv6_compact(&self) -> &[Ipv6RangeSplit64] {
        match self.dispatch_v6 {
            TableDispatchV6::Split64Compact { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const Ipv6RangeSplit64,
                        count,
                    )
                }
            }
            _ => &[],
        }
    }

    /// Alias for [`ranges_ipv4`](Self::ranges_ipv4).
    #[inline(always)]
    pub fn ranges(&self) -> &[Ipv4Range] {
        self.ranges_ipv4()
    }

    /// Alias for [`ranges_ipv4_compact`](Self::ranges_ipv4_compact).
    #[inline(always)]
    pub fn ranges_compact(&self) -> &[Ipv4RangeCompact] {
        self.ranges_ipv4_compact()
    }

    /// Alias for [`ranges_ipv6`](Self::ranges_ipv6).
    #[inline(always)]
    pub fn ranges_v6(&self) -> &[Ipv6Range] {
        self.ranges_ipv6()
    }

    /// Alias for [`ranges_ipv6_compact`](Self::ranges_ipv6_compact).
    #[inline(always)]
    pub fn ranges_v6_compact(&self) -> &[Ipv6RangeSplit64] {
        self.ranges_ipv6_compact()
    }

    /// Zero-copy verified slice of normalized profiles (20 bytes per record).
    #[inline(always)]
    pub fn profiles(&self) -> &[ProfileGen4] {
        if self.prof_count == 0 {
            return &[];
        }
        // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
        unsafe {
            std::slice::from_raw_parts(
                self.mmap.as_ptr().add(self.prof_start) as *const ProfileGen4,
                self.prof_count,
            )
        }
    }

    #[inline(always)]
    pub fn get_city(&self, idx: usize) -> &str {
        self.cities.resolve(&self.mmap, idx)
    }

    #[inline(always)]
    pub fn get_region(&self, idx: usize) -> &str {
        self.regions.resolve(&self.mmap, idx)
    }

    #[inline(always)]
    pub fn get_isp(&self, idx: usize) -> &str {
        self.isps.resolve(&self.mmap, idx)
    }

    #[inline(always)]
    fn decode_flags(&self, raw_flags: u16) -> GeoFlags {
        match &self.header {
            HeaderVariant::V4(_) => GeoFlags::from_v4(raw_flags),
            HeaderVariant::V5(_) => GeoFlags(raw_flags),
        }
    }

    #[inline(always)]
    fn lookup_raw_v4(&self, ip: u32) -> Option<(u32, u32, usize)> {
        match self.dispatch {
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
                Some((ip_from, to, *prof_ids.get(idx)? as usize))
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
                let to = ip_from.checked_add(c as u32)?;
                if ip > to {
                    return None;
                }
                let prof_ids: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(prof_off) as *const u16,
                        count,
                    )
                };
                Some((ip_from, to, *prof_ids.get(idx)? as usize))
            }
            TableDispatch::V4CompactAos { offset, count }
            | TableDispatch::V5CompactAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[Ipv4RangeCompact] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const Ipv4RangeCompact,
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
                Some((range.ip_from, range.ip_to(), range.profile_id as usize))
            }
            TableDispatch::V4StandardAos { offset, count }
            | TableDispatch::V5StandardAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[Ipv4Range] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const Ipv4Range,
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
                Some((range.ip_from, range.ip_to, range.profile_id as usize))
            }
            TableDispatch::Empty => None,
        }
    }

    /// Strict lookup for IPv4 distinguishing between true key absence (`Ok(None)`)
    /// and internal database corruption / out-of-bounds metadata references (`Err(ReaderError)`).
    #[inline]
    pub fn try_lookup_u32(&self, ip: u32) -> Result<Option<GeoRecordRef<'_>>, ReaderError> {
        let (ip_from, ip_to, profile_id) = match self.lookup_raw_v4(ip) {
            Some(v) => v,
            None => return Ok(None),
        };

        let profiles = self.profiles();
        let prof = profiles.get(profile_id).ok_or(ReaderError::Corrupted(
            "Profile ID exceeds profile table bounds",
        ))?;

        let region = self
            .regions
            .try_resolve(&self.mmap, prof.reg_idx as usize)?;
        let city = self
            .cities
            .try_resolve(&self.mmap, prof.city_idx as usize)?;
        let isp = self.isps.try_resolve(&self.mmap, prof.isp_idx as usize)?;

        Ok(Some(GeoRecordRef {
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            ip_from: ip_from as u128,
            ip_to: ip_to as u128,
            is_v6: false,
            country: prof.country_code(),
            region,
            city,
            isp,
            asn: prof.asn,
            latitude: prof.latitude(),
            longitude: prof.longitude(),
            flags: self.decode_flags(prof.flags),
        }))
    }

    /// Lookup an IPv4 integer returning a borrowed view `GeoRecordRef`.
    #[inline]
    pub fn lookup_u32(&self, ip: u32) -> Option<GeoRecordRef<'_>> {
        self.try_lookup_u32(ip).ok().flatten()
    }

    #[inline(always)]
    fn lookup_raw_v6(&self, ip: u128) -> Option<(u128, u128, usize)> {
        match self.dispatch_v6 {
            TableDispatchV6::Split64Compact { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[Ipv6RangeSplit64] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const Ipv6RangeSplit64,
                        count,
                    )
                };
                let ip_hi = (ip >> 64) as u64;
                let idx = match ranges.binary_search_by_key(&ip_hi, |r| r.ip_from_hi) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let range = ranges.get(idx)?;
                if !range.contains_hi(ip_hi) {
                    return None;
                }
                let from = (range.ip_from_hi as u128) << 64;
                let to = ((range.ip_to_hi() as u128) << 64) | 0xFFFF_FFFF_FFFF_FFFF;
                Some((from, to, range.profile_id as usize))
            }
            TableDispatchV6::StandardAos { offset, count } => {
                // SAFETY: Alignment, length, and slice bounds were pre-validated during open().
                let ranges: &[Ipv6Range] = unsafe {
                    std::slice::from_raw_parts(
                        self.mmap.as_ptr().add(offset) as *const Ipv6Range,
                        count,
                    )
                };
                let idx = match ranges.binary_search_by_key(&ip, |r| r.ip_from()) {
                    Ok(i) => i,
                    Err(0) => return None,
                    Err(i) => i - 1,
                };
                let range = ranges.get(idx)?;
                if !range.contains(ip) {
                    return None;
                }
                Some((range.ip_from(), range.ip_to(), range.profile_id() as usize))
            }
            TableDispatchV6::Empty => None,
        }
    }

    /// Strict lookup for IPv6 distinguishing between true key absence (`Ok(None)`)
    /// and internal database corruption / out-of-bounds metadata references (`Err(ReaderError)`).
    #[inline]
    pub fn try_lookup_u128(&self, ip: u128) -> Result<Option<GeoRecordRef<'_>>, ReaderError> {
        let (ip_from, ip_to, profile_id) = match self.lookup_raw_v6(ip) {
            Some(v) => v,
            None => return Ok(None),
        };

        let profiles = self.profiles();
        let prof = profiles.get(profile_id).ok_or(ReaderError::Corrupted(
            "Profile ID exceeds profile table bounds",
        ))?;

        let region = self
            .regions
            .try_resolve(&self.mmap, prof.reg_idx as usize)?;
        let city = self
            .cities
            .try_resolve(&self.mmap, prof.city_idx as usize)?;
        let isp = self.isps.try_resolve(&self.mmap, prof.isp_idx as usize)?;

        Ok(Some(GeoRecordRef {
            ip: IpAddr::V6(Ipv6Addr::from(ip)),
            ip_from,
            ip_to,
            is_v6: true,
            country: prof.country_code(),
            region,
            city,
            isp,
            asn: prof.asn,
            latitude: prof.latitude(),
            longitude: prof.longitude(),
            flags: self.decode_flags(prof.flags),
        }))
    }

    /// Lookup an IPv6 128-bit integer returning a borrowed view `GeoRecordRef`.
    #[inline]
    pub fn lookup_u128(&self, ip: u128) -> Option<GeoRecordRef<'_>> {
        self.try_lookup_u128(ip).ok().flatten()
    }

    /// Strict lookup for any `IpAddr` (IPv4 or IPv6), returning `Result<Option<GeoRecordRef>, ReaderError>`.
    #[inline]
    pub fn try_lookup_addr(&self, ip: IpAddr) -> Result<Option<GeoRecordRef<'_>>, ReaderError> {
        match ip {
            IpAddr::V4(v4) => self.try_lookup_u32(u32::from(v4)),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    self.try_lookup_u32(u32::from(v4))
                } else {
                    self.try_lookup_u128(u128::from(v6))
                }
            }
        }
    }

    /// Strict lookup for an IP address distinguishing between NotFound and Corrupted.
    #[inline(always)]
    pub fn try_lookup_ref(
        &self,
        ip: impl Into<IpAddr>,
    ) -> Result<Option<GeoRecordRef<'_>>, ReaderError> {
        self.try_lookup_addr(ip.into())
    }

    /// Looks up any `IpAddr` (IPv4 or IPv6), returning a borrowed view `GeoRecordRef`.
    #[inline]
    pub fn lookup_addr(&self, ip: IpAddr) -> Option<GeoRecordRef<'_>> {
        self.try_lookup_addr(ip).ok().flatten()
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

    /// Strict fast-path lookup returning flags or `Err(ReaderError::Corrupted)` if profile_id is invalid.
    #[inline]
    pub fn try_lookup_flags_u32(&self, ip: u32) -> Result<Option<GeoFlags>, ReaderError> {
        let (_, _, profile_id) = match self.lookup_raw_v4(ip) {
            Some(v) => v,
            None => return Ok(None),
        };
        let profiles = self.profiles();
        let prof = profiles.get(profile_id).ok_or(ReaderError::Corrupted(
            "Profile ID exceeds profile table bounds",
        ))?;
        Ok(Some(self.decode_flags(prof.flags)))
    }

    /// Fast-path lookup returning only threat/usage flags for an IPv4 address.
    /// Performs zero string resolution (`memchr`) and zero UTF-8 validation.
    #[inline]
    pub fn lookup_flags_u32(&self, ip: u32) -> Option<GeoFlags> {
        self.try_lookup_flags_u32(ip).ok().flatten()
    }

    /// Strict fast-path lookup returning flags for IPv6 or `Err(ReaderError::Corrupted)`.
    #[inline]
    pub fn try_lookup_flags_u128(&self, ip: u128) -> Result<Option<GeoFlags>, ReaderError> {
        let (_, _, profile_id) = match self.lookup_raw_v6(ip) {
            Some(v) => v,
            None => return Ok(None),
        };
        let profiles = self.profiles();
        let prof = profiles.get(profile_id).ok_or(ReaderError::Corrupted(
            "Profile ID exceeds profile table bounds",
        ))?;
        Ok(Some(self.decode_flags(prof.flags)))
    }

    /// Fast-path lookup returning only threat/usage flags for an IPv6 address.
    #[inline]
    pub fn lookup_flags_u128(&self, ip: u128) -> Option<GeoFlags> {
        self.try_lookup_flags_u128(ip).ok().flatten()
    }

    /// Fast-path lookup returning only threat/usage flags for an `IpAddr`.
    #[inline]
    pub fn lookup_flags_addr(&self, ip: IpAddr) -> Option<GeoFlags> {
        match ip {
            IpAddr::V4(v4) => self.lookup_flags_u32(u32::from(v4)),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    self.lookup_flags_u32(u32::from(v4))
                } else {
                    self.lookup_flags_u128(u128::from(v6))
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
        let (_, _, profile_id) = self.lookup_raw_v4(ip)?;
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

    /// High-throughput batch lookup for IPv4 flags writing directly into pre-allocated destination slice.
    ///
    /// Guarantees strictly zero allocations (`0 bytes heap`). Employs SIMD-friendly loop structure.
    #[inline]
    pub fn lookup_flags_batch_u32(&self, ips: &[u32], results: &mut [Option<GeoFlags>]) {
        assert_eq!(
            ips.len(),
            results.len(),
            "Input IP slice and output results slice must have identical lengths"
        );

        let arch = pulp::Arch::new();
        arch.dispatch(|| {
            let chunks = ips.chunks_exact(8);
            let rem_ips = chunks.remainder();
            let mut out_idx = 0;

            for chunk in chunks {
                for &ip in chunk {
                    results[out_idx] = self.lookup_flags_u32(ip);
                    out_idx += 1;
                }
            }

            for &ip in rem_ips {
                results[out_idx] = self.lookup_flags_u32(ip);
                out_idx += 1;
            }
        });
    }

    /// High-throughput batch lookup for IPv4 records writing directly into pre-allocated destination slice.
    ///
    /// Guarantees strictly zero allocations (`0 bytes heap`).
    #[inline]
    pub fn lookup_batch_u32<'a>(
        &'a self,
        ips: &[u32],
        results: &mut [Option<GeoRecordRef<'a>>],
    ) {
        assert_eq!(
            ips.len(),
            results.len(),
            "Input IP slice and output results slice must have identical lengths"
        );

        for (idx, &ip) in ips.iter().enumerate() {
            results[idx] = self.lookup_u32(ip);
        }
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

    /// Fast-path lookup returning the raw normalized 20-byte [`ProfileGen4`] metadata profile
    /// for an IPv4 address without resolving any strings or performing allocations.
    #[inline]
    pub fn lookup_profile_u32(&self, ip: u32) -> Option<&ProfileGen4> {
        let (_, _, profile_id) = self.lookup_raw_v4(ip)?;
        let profiles = self.profiles();
        profiles.get(profile_id)
    }

    /// Fast-path lookup returning the raw normalized 20-byte [`ProfileGen4`] metadata profile
    /// for an IPv6 128-bit address.
    #[inline]
    pub fn lookup_profile_u128(&self, ip: u128) -> Option<&ProfileGen4> {
        let (_, _, profile_id) = self.lookup_raw_v6(ip)?;
        let profiles = self.profiles();
        profiles.get(profile_id)
    }

    /// Fast-path lookup returning the raw [`ProfileGen4`] metadata profile for an `IpAddr`.
    #[inline]
    pub fn lookup_profile_addr(&self, ip: IpAddr) -> Option<&ProfileGen4> {
        match ip {
            IpAddr::V4(v4) => self.lookup_profile_u32(u32::from(v4)),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    self.lookup_profile_u32(u32::from(v4))
                } else {
                    self.lookup_profile_u128(u128::from(v6))
                }
            }
        }
    }

    /// Fast-path lookup returning the raw [`ProfileGen4`] metadata profile for an IP address.
    #[inline(always)]
    pub fn lookup_profile(&self, ip: impl Into<IpAddr>) -> Option<&ProfileGen4> {
        self.lookup_profile_addr(ip.into())
    }
}
