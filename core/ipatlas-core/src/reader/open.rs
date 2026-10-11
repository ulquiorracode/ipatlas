use memmap2::Mmap;
use std::fs::File;
use std::path::Path;
use zerocopy::FromBytes;

use crate::models::{
    ContainerFooter, HeaderV4, HeaderV5, Ipv4Range, Ipv4RangeCompact, Ipv6Range, Ipv6RangeSplit64,
    ProfileGen4, FOOTER_INDEX_SIZE, FOOTER_MAGIC, HEADER_SIZE_V4, HEADER_SIZE_V5, MAGIC,
    PROFILE_SIZE_V4, RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD, VERSION_V4_COMPACT_AOS,
    VERSION_V4_COMPACT_SOA, VERSION_V4_STANDARD, VERSION_V4_STANDARD_AOS, VERSION_V4_STANDARD_SOA,
    VERSION_V5_COMPACT_AOS, VERSION_V5_COMPACT_SOA, VERSION_V5_STANDARD, VERSION_V5_STANDARD_SOA,
};
use crate::reader::buffer::StorageBuffer;
use crate::reader::dispatch::{TableDispatch, TableDispatchV6};
use crate::reader::error::ReaderError;
use crate::reader::guide::GuideTableV4;
use crate::reader::mmap_reader::{HeaderVariant, IpAtlasReader};
use crate::reader::strings::StringTableRef;

/// Internal reader initialization coordinator.
pub(crate) struct ReaderInitializer;

impl ReaderInitializer {
    /// Opens and memory-maps an IPAtlas database from disk.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<IpAtlasReader, ReaderError> {
        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        if file_len < HEADER_SIZE_V4 as u64 {
            return Err(ReaderError::FileTooSmall(file_len));
        }

        let mmap = unsafe { Mmap::map(&file)? };
        Self::from_mmap(mmap, file_len)
    }

    /// Constructs reader from an existing memory mapping.
    pub fn from_mmap(mmap: Mmap, file_len: u64) -> Result<IpAtlasReader, ReaderError> {
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

        // Determine minimum payload end boundary (end of ISP string blob)
        let min_payload_end = (isps.data_start + isps.data_len) as u64;

        // Stage 1: Detect optional AOT Distribution Footer in the last 32 bytes of storage
        let (footer, guide_v4) = if raw_buf.len() >= min_payload_end as usize + FOOTER_INDEX_SIZE {
            let footer_bytes = &raw_buf[raw_buf.len() - FOOTER_INDEX_SIZE..];
            if footer_bytes.ends_with(&FOOTER_MAGIC) {
                if let Ok(f) = ContainerFooter::read_from_bytes(footer_bytes) {
                    if f.validate(raw_buf.len() as u64, min_payload_end).is_ok() && f.has_guide_v4()
                    {
                        let g_off = f.guide_offset as usize;
                        let g_len = f.guide_len as usize;
                        if g_off + g_len <= raw_buf.len() - FOOTER_INDEX_SIZE
                            && <[crate::reader::guide::GuideEntry]>::ref_from_bytes(
                                &raw_buf[g_off..g_off + g_len],
                            )
                            .is_ok()
                        {
                            (Some(f), GuideTableV4::from_mmap_offset(g_off))
                        } else {
                            (None, Self::build_fallback_guide(&dispatch, &storage))
                        }
                    } else {
                        (None, Self::build_fallback_guide(&dispatch, &storage))
                    }
                } else {
                    (None, Self::build_fallback_guide(&dispatch, &storage))
                }
            } else {
                (None, Self::build_fallback_guide(&dispatch, &storage))
            }
        } else {
            (None, Self::build_fallback_guide(&dispatch, &storage))
        };

        let reader = IpAtlasReader::new_raw(
            storage,
            header,
            dispatch,
            dispatch_v6,
            prof_start,
            prof_count,
            cities,
            regions,
            isps,
            guide_v4,
            footer,
        );

        #[cfg(unix)]
        {
            if let StorageBuffer::Mmap(ref m) = reader.storage_buffer() {
                // SAFETY: mmap is valid and mapped, advises kernel for binary search access pattern.
                unsafe {
                    libc::madvise(m.as_ptr() as *mut libc::c_void, m.len(), libc::MADV_RANDOM);
                }
            }
        }

        Ok(reader)
    }

    /// Builds a fallback guide table in RAM for legacy containers lacking an AOT footer.
    pub fn build_fallback_guide(dispatch: &TableDispatch, storage: &StorageBuffer) -> GuideTableV4 {
        match dispatch {
            TableDispatch::V4StandardSoa {
                ip_from_off, count, ..
            }
            | TableDispatch::V5StandardSoa {
                ip_from_off, count, ..
            }
            | TableDispatch::V4CompactSoa {
                ip_from_off, count, ..
            }
            | TableDispatch::V5CompactSoa {
                ip_from_off, count, ..
            } => {
                let ip_froms: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(*ip_from_off) as *const u32,
                        *count,
                    )
                };
                GuideTableV4::from_soa_ip_froms(ip_froms)
            }
            TableDispatch::V4CompactAos { offset, count }
            | TableDispatch::V5CompactAos { offset, count } => {
                let ranges: &[Ipv4RangeCompact] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(*offset) as *const Ipv4RangeCompact,
                        *count,
                    )
                };
                GuideTableV4::from_ranges_compact(ranges)
            }
            TableDispatch::V4StandardAos { offset, count }
            | TableDispatch::V5StandardAos { offset, count } => {
                let ranges: &[Ipv4Range] = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().add(*offset) as *const Ipv4Range,
                        *count,
                    )
                };
                GuideTableV4::from_ranges_standard(ranges)
            }
            TableDispatch::Empty => GuideTableV4::new(),
        }
    }
}
