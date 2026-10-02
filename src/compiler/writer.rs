use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use flate2::write::GzEncoder;
use flate2::Compression;
use zerocopy::IntoBytes;

use crate::compiler::sweep::{MergedEntry, MergedEntryV6};
use crate::models::{
    Crc32, HeaderV5, OptimizationConfig, ProfileV4, RangeV4, RangeV4Compact, RangeV6,
    HEADER_SIZE_V5, MAGIC, PROFILE_SIZE_V4, RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD,
    RECORD_SIZE_V6, VERSION_V5_COMPACT, VERSION_V5_STANDARD,
};

#[derive(Default)]
pub struct StringPool {
    map: HashMap<String, u32>,
    pub offsets: Vec<u32>,
    pub blob: Vec<u8>,
}

impl StringPool {
    pub fn new() -> Self {
        let mut pool = Self {
            map: HashMap::new(),
            offsets: Vec::new(),
            blob: Vec::new(),
        };
        // Index 0 is always the empty string
        pool.offsets.push(0);
        pool.blob.push(0);
        pool.map.insert(String::new(), 0);
        pool.map.insert("-".to_string(), 0);
        pool
    }

    pub fn get_or_insert(&mut self, s: &str, prune_empty: bool) -> u32 {
        if prune_empty && (s.is_empty() || s == "-") {
            return 0;
        }
        if let Some(&idx) = self.map.get(s) {
            return idx;
        }
        let idx = self.offsets.len() as u32;
        let offset = self.blob.len() as u32;
        self.offsets.push(offset);
        self.blob.extend_from_slice(s.as_bytes());
        self.blob.push(0); // Null terminator
        self.map.insert(s.to_string(), idx);
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
    pub gz_size: Option<u64>,
    pub zst_size: Option<u64>,
    pub elapsed_secs: f64,
    pub is_compact: bool,
    pub crc32: u32,
    pub warnings: Vec<String>,
    pub bin_path: PathBuf,
}

enum RangeStorage {
    Standard(Vec<RangeV4>),
    Compact(Vec<RangeV4Compact>),
}

pub struct DatabaseWriter {
    storage: RangeStorage,
    ranges_v6: Vec<RangeV6>,
    original_records: usize,
    profiles: Vec<ProfileV4>,
    profile_map: HashMap<ProfileV4, u32>,
    cities: StringPool,
    regions: StringPool,
    isps: StringPool,
    opt: OptimizationConfig,
    warnings: Vec<String>,
    has_region_overflow: bool,
    has_isp_overflow: bool,
}

impl DatabaseWriter {
    pub fn new(opt: OptimizationConfig) -> Self {
        let storage = if opt.compact_ranges {
            RangeStorage::Compact(Vec::new())
        } else {
            RangeStorage::Standard(Vec::new())
        };

        Self {
            storage,
            ranges_v6: Vec::new(),
            original_records: 0,
            profiles: Vec::new(),
            profile_map: HashMap::new(),
            cities: StringPool::new(),
            regions: StringPool::new(),
            isps: StringPool::new(),
            opt,
            warnings: Vec::new(),
            has_region_overflow: false,
            has_isp_overflow: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn intern_profile(
        &mut self,
        city: &str,
        region: &str,
        isp: &str,
        asn: u32,
        country: [u8; 2],
        flags: u16,
        lat_fixed: i16,
        lon_fixed: i16,
    ) -> u32 {
        let city_idx = self.cities.get_or_insert(city, self.opt.prune_empty);

        let raw_reg_idx = self.regions.get_or_insert(region, self.opt.prune_empty);
        let reg_idx = if raw_reg_idx <= u16::MAX as u32 {
            raw_reg_idx as u16
        } else {
            if !self.has_region_overflow {
                self.has_region_overflow = true;
                self.warnings.push(format!(
                    "Region dictionary size ({}) exceeded u16::MAX (65535). Saturated overflow to 0.",
                    raw_reg_idx + 1
                ));
            }
            0
        };

        let raw_isp_idx = self.isps.get_or_insert(isp, self.opt.prune_empty);
        let isp_idx = if raw_isp_idx <= u16::MAX as u32 {
            raw_isp_idx as u16
        } else {
            if !self.has_isp_overflow {
                self.has_isp_overflow = true;
                self.warnings.push(format!(
                    "ISP dictionary size ({}) exceeded u16::MAX (65535). Saturated overflow to 0.",
                    raw_isp_idx + 1
                ));
            }
            0
        };

        let prof = ProfileV4::new(
            city_idx, asn, country, reg_idx, isp_idx, flags, lat_fixed, lon_fixed,
        );

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

    /// Ingests a stream of merged IPv4 entries, building range intervals, profiles, and string pools.
    pub fn ingest_all<I: Iterator<Item = MergedEntry>>(&mut self, entries: I) {
        for entry in entries {
            self.original_records += 1;
            let profile_id = self.intern_profile(
                &entry.city,
                &entry.region,
                &entry.isp,
                entry.asn,
                entry.country,
                entry.flags,
                entry.lat_fixed,
                entry.lon_fixed,
            );

            // If profile_id exceeds u16::MAX in Compact mode, transparently fallback to Standard
            if let RangeStorage::Compact(vec) = &mut self.storage {
                if profile_id > u16::MAX as u32 {
                    self.warnings.push(format!(
                        "Profile count ({}) exceeds u16::MAX (65535). Automatically falling back from V4-Compact to V4-Standard layout.",
                        profile_id + 1
                    ));
                    let mut std_vec = Vec::with_capacity(vec.len() + 1);
                    for r in vec.drain(..) {
                        std_vec.push(RangeV4::new(r.ip_from, r.ip_to(), r.profile_id as u32));
                    }
                    self.storage = RangeStorage::Standard(std_vec);
                }
            }

            match &mut self.storage {
                RangeStorage::Standard(vec) => {
                    vec.push(RangeV4::new(entry.ip_from, entry.ip_to, profile_id));
                }
                RangeStorage::Compact(vec) => {
                    // Split intervals wider than u16::MAX so they fit in compact count field
                    let mut curr_from = entry.ip_from;
                    let target_to = entry.ip_to;
                    let prof_u16 = profile_id as u16;

                    while curr_from <= target_to {
                        let span = (target_to - curr_from).min(u16::MAX as u32);
                        vec.push(RangeV4Compact::new(curr_from, span as u16, prof_u16));
                        if span == u16::MAX as u32 && curr_from < u32::MAX - span {
                            curr_from += span + 1;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Ingests a stream of merged IPv6 entries.
    pub fn ingest_all_v6<I: Iterator<Item = MergedEntryV6>>(&mut self, entries: I) {
        for entry in entries {
            self.original_records += 1;
            let profile_id = self.intern_profile(
                &entry.city,
                &entry.region,
                &entry.isp,
                entry.asn,
                entry.country,
                entry.flags,
                entry.lat_fixed,
                entry.lon_fixed,
            );

            self.ranges_v6
                .push(RangeV6::new(entry.ip_from, entry.ip_to, profile_id));
        }
    }

    /// Atomically writes the Generation V5 database binary and generates .gz / .zst distributions.
    pub fn write_to_file<P: AsRef<Path>>(
        &self,
        output_path: P,
        write_gz: bool,
        write_zst: bool,
    ) -> Result<CompilationStats, std::io::Error> {
        let start = Instant::now();
        let path = output_path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let is_compact = matches!(self.storage, RangeStorage::Compact(_));
        let total_records_v4 = match &self.storage {
            RangeStorage::Standard(vec) => vec.len() as u32,
            RangeStorage::Compact(vec) => vec.len() as u32,
        };
        let total_records_v6 = self.ranges_v6.len() as u32;
        let profile_count = self.profiles.len() as u32;

        let record_size_v4 = if is_compact {
            RECORD_SIZE_V4_COMPACT
        } else {
            RECORD_SIZE_V4_STANDARD
        };
        let record_size_v6 = RECORD_SIZE_V6;

        let version = if is_compact {
            VERSION_V5_COMPACT
        } else {
            VERSION_V5_STANDARD
        };

        let records_v4_bytes = (total_records_v4 as usize) * (record_size_v4 as usize);
        let records_v6_bytes = (total_records_v6 as usize) * (record_size_v6 as usize);
        let prof_size = (profile_count as usize) * PROFILE_SIZE_V4;

        let prof_offset = (HEADER_SIZE_V5 + records_v4_bytes + records_v6_bytes) as u32;
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

        let header = HeaderV5 {
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
            reserved: 0,
            crc32: 0,
        };

        // Struct to ensure cleanup of temporary files if an error occurs
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
            let mut writer = BufWriter::with_capacity(1024 * 1024, file);

            // Write initial header placeholder
            writer.write_all(header.as_bytes())?;

            let mut crc = Crc32::new();

            // Write and CRC IPv4 ranges
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

            // Write and CRC IPv6 ranges
            for r in &self.ranges_v6 {
                let bytes = r.as_bytes();
                crc.update(bytes);
                writer.write_all(bytes)?;
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

            std::mem::forget(guard);
        }

        // Atomic rename into target path
        std::fs::rename(&tmp_bin_path, path)?;
        let raw_size = std::fs::metadata(path)?.len();

        // 2. Atomic Gzip compression (.bin.gz)
        let gz_size = if write_gz {
            let gz_path = path.with_extension(format!(
                "{}.gz",
                path.extension().and_then(|s| s.to_str()).unwrap_or("bin")
            ));
            let tmp_gz_path = gz_path.with_extension(format!("tmp.{}", std::process::id()));
            {
                let guard = TempFileGuard(&tmp_gz_path);
                let gz_file = File::create(&tmp_gz_path)?;
                let mut encoder = GzEncoder::new(BufWriter::new(gz_file), Compression::best());
                let mut in_file = File::open(path)?;
                std::io::copy(&mut in_file, &mut encoder)?;
                let mut inner = encoder.finish()?;
                inner.flush()?;
                inner.get_ref().sync_all()?;
                std::mem::forget(guard);
            }
            std::fs::rename(&tmp_gz_path, &gz_path)?;
            Some(std::fs::metadata(&gz_path)?.len())
        } else {
            None
        };

        // 3. Atomic Zstandard compression (.bin.zst) at maximum level 19
        let zst_size = if write_zst {
            let zst_path = path.with_extension(format!(
                "{}.zst",
                path.extension().and_then(|s| s.to_str()).unwrap_or("bin")
            ));
            let tmp_zst_path = zst_path.with_extension(format!("tmp.{}", std::process::id()));
            {
                let guard = TempFileGuard(&tmp_zst_path);
                let zst_file = File::create(&tmp_zst_path)?;
                let mut encoder = zstd::stream::write::Encoder::new(BufWriter::new(zst_file), 19)?;
                let mut in_file = File::open(path)?;
                let mut buffer = [0u8; 128 * 1024];
                loop {
                    let n = in_file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    encoder.write_all(&buffer[..n])?;
                }
                let mut inner = encoder.finish()?;
                inner.flush()?;
                inner.get_ref().sync_all()?;
                std::mem::forget(guard);
            }
            std::fs::rename(&tmp_zst_path, &zst_path)?;
            Some(std::fs::metadata(&zst_path)?.len())
        } else {
            None
        };

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
            gz_size,
            zst_size,
            elapsed_secs: elapsed,
            is_compact,
            crc32: calculated_crc32,
            warnings: self.warnings.clone(),
            bin_path: path.to_path_buf(),
        })
    }
}
