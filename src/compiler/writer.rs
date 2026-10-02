use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use flate2::write::GzEncoder;
use flate2::Compression;
use zerocopy::IntoBytes;

use crate::compiler::sweep::MergedEntry;
use crate::models::{
    HeaderV4, OptimizationConfig, ProfileV4, RangeV4, HEADER_SIZE_V4, MAGIC, PROFILE_SIZE_V4,
    RECORD_SIZE_V4, VERSION_V4,
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
    pub profiles: usize,
    pub cities: usize,
    pub regions: usize,
    pub isps: usize,
    pub raw_size: u64,
    pub gz_size: Option<u64>,
    pub zst_size: Option<u64>,
    pub elapsed_secs: f64,
    pub bin_path: PathBuf,
}

pub struct DatabaseWriter {
    ranges: Vec<RangeV4>,
    profiles: Vec<ProfileV4>,
    profile_map: HashMap<ProfileV4, u32>,
    cities: StringPool,
    regions: StringPool,
    isps: StringPool,
    opt: OptimizationConfig,
}

impl DatabaseWriter {
    pub fn new(opt: OptimizationConfig) -> Self {
        Self {
            ranges: Vec::new(),
            profiles: Vec::new(),
            profile_map: HashMap::new(),
            cities: StringPool::new(),
            regions: StringPool::new(),
            isps: StringPool::new(),
            opt,
        }
    }

    /// Ingests a stream of merged entries, building range intervals, profiles, and string pools.
    pub fn ingest_all<I: Iterator<Item = MergedEntry>>(&mut self, entries: I) {
        for entry in entries {
            let city_idx = self.cities.get_or_insert(&entry.city, self.opt.prune_empty);
            let reg_idx =
                self.regions
                    .get_or_insert(&entry.region, self.opt.prune_empty) as u16;
            let isp_idx = self.isps.get_or_insert(&entry.isp, self.opt.prune_empty) as u16;

            let prof = ProfileV4::new(
                city_idx,
                entry.asn,
                entry.country,
                reg_idx,
                isp_idx,
                entry.flags,
                entry.lat_fixed,
                entry.lon_fixed,
            );

            let profile_id = if self.opt.dedup_profiles {
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
            };

            self.ranges
                .push(RangeV4::new(entry.ip_from, entry.ip_to, profile_id));
        }
    }

    /// Writes the compiled binary database and generates .gz and .zst compressed distributions.
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

        let total_records = self.ranges.len() as u32;
        let profile_count = self.profiles.len() as u32;

        let records_size = (total_records as usize) * (RECORD_SIZE_V4 as usize);
        let prof_size = (profile_count as usize) * PROFILE_SIZE_V4;

        let prof_offset = (HEADER_SIZE_V4 + records_size) as u32;
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

        let header = HeaderV4 {
            magic: MAGIC,
            version: VERSION_V4,
            total_records,
            record_size: RECORD_SIZE_V4,
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
        };

        // 1. Write binary database
        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);

        writer.write_all(header.as_bytes())?;

        for r in &self.ranges {
            writer.write_all(r.as_bytes())?;
        }

        for p in &self.profiles {
            writer.write_all(p.as_bytes())?;
        }

        for off in &self.cities.offsets {
            writer.write_all(&off.to_le_bytes())?;
        }
        writer.write_all(&self.cities.blob)?;

        for off in &self.regions.offsets {
            writer.write_all(&off.to_le_bytes())?;
        }
        writer.write_all(&self.regions.blob)?;

        for off in &self.isps.offsets {
            writer.write_all(&off.to_le_bytes())?;
        }
        writer.write_all(&self.isps.blob)?;

        writer.flush()?;
        drop(writer);

        let raw_size = std::fs::metadata(path)?.len();

        // 2. Native Gzip compression (.bin.gz)
        let gz_size = if write_gz {
            let gz_path = path.with_extension(format!(
                "{}.gz",
                path.extension().and_then(|s| s.to_str()).unwrap_or("bin")
            ));
            let gz_file = File::create(&gz_path)?;
            let mut encoder = GzEncoder::new(BufWriter::new(gz_file), Compression::best());
            let mut in_file = File::open(path)?;
            std::io::copy(&mut in_file, &mut encoder)?;
            encoder.finish()?;
            Some(std::fs::metadata(&gz_path)?.len())
        } else {
            None
        };

        // 3. Native Zstandard compression (.bin.zst) at maximum level 19
        let zst_size = if write_zst {
            let zst_path = path.with_extension(format!(
                "{}.zst",
                path.extension().and_then(|s| s.to_str()).unwrap_or("bin")
            ));
            let zst_file = File::create(&zst_path)?;
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
            encoder.finish()?;
            Some(std::fs::metadata(&zst_path)?.len())
        } else {
            None
        };

        let elapsed = start.elapsed().as_secs_f64();

        Ok(CompilationStats {
            records: self.ranges.len(),
            profiles: self.profiles.len(),
            cities: self.cities.offsets.len(),
            regions: self.regions.offsets.len(),
            isps: self.isps.offsets.len(),
            raw_size,
            gz_size,
            zst_size,
            elapsed_secs: elapsed,
            bin_path: path.to_path_buf(),
        })
    }
}
