use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use zerocopy::IntoBytes;

use crate::compiler::sweep::{MergedEntry, MergedEntryV6};
use crate::models::{
    Crc32, HeaderGen5, Ipv4Range, Ipv4RangeCompact, Ipv6Range, Ipv6RangeSplit64,
    OptimizationConfig, ProfileGen4, RecordFamily, StorageLayout, HEADER_FLAG_EMBEDDED_ZSTD,
    HEADER_SIZE_GEN5, MAGIC, PROFILE_SIZE_GEN4, RECORD_SIZE_IPV4_COMPACT,
    RECORD_SIZE_IPV4_STANDARD, RECORD_SIZE_IPV6_COMPACT, RECORD_SIZE_IPV6_STANDARD,
    VERSION_V5_COMPACT_AOS, VERSION_V5_COMPACT_SOA, VERSION_V5_STANDARD_AOS,
    VERSION_V5_STANDARD_SOA,
};

#[derive(Default)]
pub struct StringPool {
    map: HashMap<String, u32>,
    pub offsets: Vec<u32>,
    pub blob: Vec<u8>,
    last_str: String,
    last_idx: u32,
}

impl StringPool {
    pub fn new() -> Self {
        let mut pool = Self {
            map: HashMap::new(),
            offsets: Vec::new(),
            blob: Vec::new(),
            last_str: String::new(),
            last_idx: 0,
        };
        // Index 0 is always the empty string
        pool.offsets.push(0);
        pool.blob.push(0);
        pool.map.insert(String::new(), 0);
        pool.map.insert("-".to_string(), 0);
        pool
    }

    /// Fast lookup and insertion with 1-element Last-Value Cache (LVC).
    /// Since geographic and ISP blocks in sorted CSV files cluster together,
    /// LVC absorbs 80-95% of queries without querying the HashMap.
    #[inline]
    pub fn get_or_insert(&mut self, s: &str, prune_empty: bool) -> u32 {
        if prune_empty && (s.is_empty() || s == "-") {
            return 0;
        }
        if !self.last_str.is_empty() && s == self.last_str {
            return self.last_idx;
        }
        if let Some(&idx) = self.map.get(s) {
            self.last_str.clear();
            self.last_str.push_str(s);
            self.last_idx = idx;
            return idx;
        }
        let idx = self.offsets.len() as u32;
        let offset = self.blob.len() as u32;
        self.offsets.push(offset);
        self.blob.extend_from_slice(s.as_bytes());
        self.blob.push(0); // Null terminator
        self.map.insert(s.to_string(), idx);
        self.last_str.clear();
        self.last_str.push_str(s);
        self.last_idx = idx;
        idx
    }
}

#[derive(Clone, Debug)]
pub struct CompilationStats {
    pub records: usize,
    pub records_v4: usize,
    pub records_v6: usize,
    pub original_records: usize,
    pub profiles: usize,
    pub cities: usize,
    pub regions: usize,
    pub isps: usize,
    pub raw_size: u64,
    pub elapsed_secs: f64,
    pub is_compact: bool,
    pub is_soa: bool,
    pub crc32: u32,
    pub warnings: Vec<String>,
    pub bin_path: PathBuf,
}

enum RangeStorage {
    Standard(Vec<Ipv4Range>),
    Compact(Vec<Ipv4RangeCompact>),
}

enum RangeStorageV6 {
    Standard(Vec<Ipv6Range>),
    Compact(Vec<Ipv6RangeSplit64>),
}

pub struct DatabaseWriter {
    storage: RangeStorage,
    storage_v6: RangeStorageV6,
    original_records: usize,
    profiles: Vec<ProfileGen4>,
    profile_map: HashMap<ProfileGen4, u32>,
    cities: StringPool,
    regions: StringPool,
    isps: StringPool,
    opt: OptimizationConfig,
    warnings: Vec<String>,
}

impl DatabaseWriter {
    pub fn new(opt: OptimizationConfig) -> Self {
        let is_compact = opt.compact_ranges || opt.family == RecordFamily::Compact;
        let storage = if is_compact {
            RangeStorage::Compact(Vec::new())
        } else {
            RangeStorage::Standard(Vec::new())
        };
        // IPv6 Split-64 (16B) is lossy/over-approximating on sub-/64 spans and requires explicit opt-in (opt.split64_v6).
        // By default, IPv6 ranges remain lossless Standard (36B) even under compact IPv4 family.
        let storage_v6 = if opt.split64_v6 {
            RangeStorageV6::Compact(Vec::new())
        } else {
            RangeStorageV6::Standard(Vec::new())
        };

        Self {
            storage,
            storage_v6,
            original_records: 0,
            profiles: Vec::new(),
            profile_map: HashMap::new(),
            cities: StringPool::new(),
            regions: StringPool::new(),
            isps: StringPool::new(),
            opt,
            warnings: Vec::new(),
        }
    }

    #[inline]
    pub fn set_pools(&mut self, cities: StringPool, regions: StringPool, isps: StringPool) {
        self.cities = cities;
        self.regions = regions;
        self.isps = isps;
    }

    #[inline]
    fn get_or_create_profile(&mut self, prof: ProfileGen4) -> u32 {
        if self.opt.dedup_profiles {
            if let Some(&id) = self.profile_map.get(&prof) {
                id
            } else {
                let id = self.profiles.len() as u32;
                self.profiles.push(prof);
                self.profile_map.insert(prof, id);
                id
            }
        } else {
            let id = self.profiles.len() as u32;
            self.profiles.push(prof);
            id
        }
    }

    /// Ingests a stream of merged IPv4 entries without string allocations.
    pub fn ingest_all<I: Iterator<Item = MergedEntry>>(&mut self, entries: I) {
        for entry in entries {
            self.original_records += 1;
            let prof = ProfileGen4::new(
                entry.city_idx,
                entry.asn,
                entry.country,
                entry.reg_idx,
                entry.isp_idx,
                entry.flags,
                entry.lat_fixed,
                entry.lon_fixed,
            );
            let profile_id = self.get_or_create_profile(prof);

            // If profile_id exceeds u16::MAX in Compact mode, transparently fallback to Standard
            if let RangeStorage::Compact(vec) = &mut self.storage {
                if profile_id > u16::MAX as u32 {
                    self.warnings.push(format!(
                        "Profile count ({}) exceeds u16::MAX (65535). Automatically falling back from V4-Compact to V4-Standard layout.",
                        profile_id + 1
                    ));
                    let mut std_vec = Vec::with_capacity(vec.len() + 1);
                    for r in vec.drain(..) {
                        std_vec.push(Ipv4Range::new(r.ip_from, r.ip_to(), r.profile_id as u32));
                    }
                    self.storage = RangeStorage::Standard(std_vec);
                }
            }

            match &mut self.storage {
                RangeStorage::Standard(vec) => {
                    vec.push(Ipv4Range::new(entry.ip_from, entry.ip_to, profile_id));
                }
                RangeStorage::Compact(vec) => {
                    crate::compiler::adapters::CompactRangePacker::pack_span(
                        entry.ip_from,
                        entry.ip_to,
                        profile_id as u16,
                        vec,
                    );
                }
            }
        }
    }

    /// Ingests a stream of merged IPv6 entries without string allocations.
    pub fn ingest_all_v6<I: Iterator<Item = MergedEntryV6>>(&mut self, entries: I) {
        for entry in entries {
            self.original_records += 1;
            let prof = ProfileGen4::new(
                entry.city_idx,
                entry.asn,
                entry.country,
                entry.reg_idx,
                entry.isp_idx,
                entry.flags,
                entry.lat_fixed,
                entry.lon_fixed,
            );
            let profile_id = self.get_or_create_profile(prof);

            match &mut self.storage_v6 {
                RangeStorageV6::Standard(vec) => {
                    vec.push(Ipv6Range::new(entry.ip_from, entry.ip_to, profile_id));
                }
                RangeStorageV6::Compact(vec) => {
                    crate::compiler::adapters::Split64RangePacker::pack_span(
                        entry.ip_from,
                        entry.ip_to,
                        profile_id,
                        vec,
                    );
                }
            }
        }
    }

    /// Atomically writes the database binary image directly to file.
    pub fn write_to_file<P: AsRef<Path>>(
        &self,
        output_path: P,
    ) -> Result<CompilationStats, std::io::Error> {
        let start = Instant::now();
        let path = output_path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let is_compact = matches!(self.storage, RangeStorage::Compact(_));
        let is_compact_v6 = matches!(self.storage_v6, RangeStorageV6::Compact(_));
        let is_soa = self.opt.layout == StorageLayout::Soa;
        let total_records_v4 = match &self.storage {
            RangeStorage::Standard(vec) => vec.len() as u32,
            RangeStorage::Compact(vec) => vec.len() as u32,
        };
        let total_records_v6 = match &self.storage_v6 {
            RangeStorageV6::Standard(vec) => vec.len() as u32,
            RangeStorageV6::Compact(vec) => vec.len() as u32,
        };
        let profile_count = self.profiles.len() as u32;

        let record_size_v4 = if is_compact {
            RECORD_SIZE_IPV4_COMPACT
        } else {
            RECORD_SIZE_IPV4_STANDARD
        };
        let record_size_v6 = if is_compact_v6 {
            RECORD_SIZE_IPV6_COMPACT
        } else {
            RECORD_SIZE_IPV6_STANDARD
        };

        let version = match (is_compact, is_soa) {
            (true, true) => VERSION_V5_COMPACT_SOA,
            (true, false) => VERSION_V5_COMPACT_AOS,
            (false, true) => VERSION_V5_STANDARD_SOA,
            (false, false) => VERSION_V5_STANDARD_AOS,
        };

        let records_v4_bytes = (total_records_v4 as usize) * (record_size_v4 as usize);
        let records_v6_bytes = (total_records_v6 as usize) * (record_size_v6 as usize);
        let prof_size = (profile_count as usize) * PROFILE_SIZE_GEN4;

        let prof_offset = (HEADER_SIZE_GEN5 + records_v4_bytes + records_v6_bytes) as u32;
        let c_idx_off = prof_offset + prof_size as u32;
        let c_idx_len = (self.cities.offsets.len() * 4) as u32;
        let c_data_off = c_idx_off + c_idx_len;
        let c_data_len = self.cities.blob.len() as u32;

        let r_idx_off = c_data_off + c_data_len;
        let r_idx_len = (self.regions.offsets.len() * 4) as u32;
        let r_data_off = r_idx_off + r_idx_len;
        let r_data_len = self.regions.blob.len() as u32;

        let i_idx_off = r_data_off + r_data_len;
        let i_idx_len = (self.isps.offsets.len() * 4) as u32;
        let i_data_off = i_idx_off + i_idx_len;
        let i_data_len = self.isps.blob.len() as u32;

        let mut header = HeaderGen5 {
            magic: MAGIC,
            version,
            total_records_v4,
            record_size_v4,
            total_records_v6,
            record_size_v6,
            profile_count,
            profile_offset: prof_offset,
            city_count: self.cities.offsets.len() as u32,
            city_idx_off: c_idx_off,
            city_data_off: c_data_off,
            city_data_len: c_data_len,
            region_count: self.regions.offsets.len() as u32,
            region_idx_off: r_idx_off,
            region_data_off: r_data_off,
            region_data_len: r_data_len,
            isp_count: self.isps.offsets.len() as u32,
            isp_idx_off: i_idx_off,
            isp_data_off: i_data_off,
            isp_data_len: i_data_len,
            reserved: if self.opt.embedded_zstd {
                HEADER_FLAG_EMBEDDED_ZSTD
            } else {
                0
            },
            crc32: 0,
        };

        struct TempFileGuard<'a>(&'a Path);
        impl<'a> Drop for TempFileGuard<'a> {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0);
            }
        }

        // 1. Atomic write to temporary file with CRC32 tracking
        let tmp_bin_path = path.with_extension(format!("tmp.{}", std::process::id()));
        let calculated_crc32;
        {
            let guard = TempFileGuard(&tmp_bin_path);
            let file = File::create(&tmp_bin_path)?;

            if self.opt.embedded_zstd {
                // Buffer uncompressed payload in memory, compute its CRC32, and compress via zstd-19
                let mut payload =
                    Vec::with_capacity(records_v4_bytes + records_v6_bytes + prof_size);
                if is_soa {
                    match &self.storage {
                        RangeStorage::Compact(vec) => {
                            for r in vec {
                                payload.extend_from_slice(&r.ip_from.to_le_bytes());
                            }
                            for r in vec {
                                payload.extend_from_slice(&r.count.to_le_bytes());
                            }
                            for r in vec {
                                payload.extend_from_slice(&r.profile_id.to_le_bytes());
                            }
                        }
                        RangeStorage::Standard(vec) => {
                            for r in vec {
                                payload.extend_from_slice(&r.ip_from.to_le_bytes());
                            }
                            for r in vec {
                                payload.extend_from_slice(&r.ip_to.to_le_bytes());
                            }
                            for r in vec {
                                payload.extend_from_slice(&r.profile_id.to_le_bytes());
                            }
                        }
                    }
                } else {
                    match &self.storage {
                        RangeStorage::Standard(vec) => {
                            for r in vec {
                                payload.extend_from_slice(r.as_bytes());
                            }
                        }
                        RangeStorage::Compact(vec) => {
                            for r in vec {
                                payload.extend_from_slice(r.as_bytes());
                            }
                        }
                    }
                }
                match &self.storage_v6 {
                    RangeStorageV6::Standard(vec) => {
                        for r in vec {
                            payload.extend_from_slice(r.as_bytes());
                        }
                    }
                    RangeStorageV6::Compact(vec) => {
                        for r in vec {
                            payload.extend_from_slice(r.as_bytes());
                        }
                    }
                }
                for p in &self.profiles {
                    payload.extend_from_slice(p.as_bytes());
                }
                for off in &self.cities.offsets {
                    payload.extend_from_slice(&off.to_le_bytes());
                }
                payload.extend_from_slice(&self.cities.blob);
                for off in &self.regions.offsets {
                    payload.extend_from_slice(&off.to_le_bytes());
                }
                payload.extend_from_slice(&self.regions.blob);
                for off in &self.isps.offsets {
                    payload.extend_from_slice(&off.to_le_bytes());
                }
                payload.extend_from_slice(&self.isps.blob);

                let mut crc = Crc32::new();
                crc.update(&payload);
                calculated_crc32 = crc.finalize();
                header.crc32 = calculated_crc32;

                let compressed_payload = zstd::stream::encode_all(&payload[..], 19)?;

                let mut writer = BufWriter::with_capacity(1024 * 1024, file);
                writer.write_all(header.as_bytes())?;
                writer.write_all(&compressed_payload)?;
                writer.flush()?;
                let inner_file = writer.get_mut();
                inner_file.sync_all()?;
            } else {
                let mut writer = BufWriter::with_capacity(1024 * 1024, file);

                // Write initial header placeholder
                writer.write_all(header.as_bytes())?;

                let mut crc = Crc32::new();

                // Write and CRC IPv4 ranges
                if is_soa {
                    match &self.storage {
                        RangeStorage::Compact(vec) => {
                            for r in vec {
                                let bytes = r.ip_from.to_le_bytes();
                                crc.update(&bytes);
                                writer.write_all(&bytes)?;
                            }
                            for r in vec {
                                let bytes = r.count.to_le_bytes();
                                crc.update(&bytes);
                                writer.write_all(&bytes)?;
                            }
                            for r in vec {
                                let bytes = r.profile_id.to_le_bytes();
                                crc.update(&bytes);
                                writer.write_all(&bytes)?;
                            }
                        }
                        RangeStorage::Standard(vec) => {
                            for r in vec {
                                let bytes = r.ip_from.to_le_bytes();
                                crc.update(&bytes);
                                writer.write_all(&bytes)?;
                            }
                            for r in vec {
                                let bytes = r.ip_to.to_le_bytes();
                                crc.update(&bytes);
                                writer.write_all(&bytes)?;
                            }
                            for r in vec {
                                let bytes = r.profile_id.to_le_bytes();
                                crc.update(&bytes);
                                writer.write_all(&bytes)?;
                            }
                        }
                    }
                } else {
                    match &self.storage {
                        RangeStorage::Standard(vec) => {
                            for r in vec {
                                let bytes = r.as_bytes();
                                crc.update(bytes);
                                writer.write_all(bytes)?;
                            }
                        }
                        RangeStorage::Compact(vec) => {
                            for r in vec {
                                let bytes = r.as_bytes();
                                crc.update(bytes);
                                writer.write_all(bytes)?;
                            }
                        }
                    }
                }

                // Write and CRC IPv6 ranges
                match &self.storage_v6 {
                    RangeStorageV6::Standard(vec) => {
                        for r in vec {
                            let bytes = r.as_bytes();
                            crc.update(bytes);
                            writer.write_all(bytes)?;
                        }
                    }
                    RangeStorageV6::Compact(vec) => {
                        for r in vec {
                            let bytes = r.as_bytes();
                            crc.update(bytes);
                            writer.write_all(bytes)?;
                        }
                    }
                }

                // Write and CRC profiles
                for p in &self.profiles {
                    let bytes = p.as_bytes();
                    crc.update(bytes);
                    writer.write_all(bytes)?;
                }

                // Write and CRC city table
                for off in &self.cities.offsets {
                    let bytes = off.to_le_bytes();
                    crc.update(&bytes);
                    writer.write_all(&bytes)?;
                }
                crc.update(&self.cities.blob);
                writer.write_all(&self.cities.blob)?;

                // Write and CRC region table
                for off in &self.regions.offsets {
                    let bytes = off.to_le_bytes();
                    crc.update(&bytes);
                    writer.write_all(&bytes)?;
                }
                crc.update(&self.regions.blob);
                writer.write_all(&self.regions.blob)?;

                // Write and CRC ISP table
                for off in &self.isps.offsets {
                    let bytes = off.to_le_bytes();
                    crc.update(&bytes);
                    writer.write_all(&bytes)?;
                }
                crc.update(&self.isps.blob);
                writer.write_all(&self.isps.blob)?;

                calculated_crc32 = crc.finalize();

                // Seek back to write calculated CRC32 in header (offset 76)
                writer.flush()?;
                let inner_file = writer.get_mut();
                inner_file.seek(SeekFrom::Start(76))?;
                inner_file.write_all(&calculated_crc32.to_le_bytes())?;
                inner_file.sync_all()?;
            }

            std::mem::forget(guard);
        }

        // Atomic rename into target path
        std::fs::rename(&tmp_bin_path, path)?;
        let raw_size = std::fs::metadata(path)?.len();

        let elapsed = start.elapsed().as_secs_f64();

        Ok(CompilationStats {
            records: (total_records_v4 + total_records_v6) as usize,
            records_v4: total_records_v4 as usize,
            records_v6: total_records_v6 as usize,
            original_records: self.original_records,
            profiles: self.profiles.len(),
            cities: self.cities.offsets.len(),
            regions: self.regions.offsets.len(),
            isps: self.isps.offsets.len(),
            raw_size,
            elapsed_secs: elapsed,
            is_compact,
            is_soa,
            crc32: calculated_crc32,
            warnings: self.warnings.clone(),
            bin_path: path.to_path_buf(),
        })
    }
}
