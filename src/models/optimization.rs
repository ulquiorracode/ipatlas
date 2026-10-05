/// Fine-grained optimization rules for database transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OptRule {
    /// Merge adjacent intervals [A, B] and [B+1, C] with identical feature profiles.
    Coalesce,
    /// Pool identical metadata tuples into normalized Profile IDs.
    DedupProfiles,
    /// Trim whitespace and deduplicate string entries case-sensitively.
    NormalizeStrings,
    /// Quantize coordinates symmetrically to 1 decimal place (~10km) without zero-bias.
    LossyCoords,
    /// Prune empty/dash string entries so they reference index 0.
    PruneEmpty,
    /// Strip sub-category threat flags, collapsing into generic proxy flag.
    /// Strip sub-category threat flags, collapsing into generic proxy flag.
    CollapseThreats,
    /// Format V4.1 Compact: 8-byte range intervals (ip_from: u32, count: u16, profile_id: u16).
    CompactRanges,
    /// Format IPv6 Split-64: 16-byte lossy /64 range intervals (over-approximates sub-/64 spans).
    Split64V6,
    /// Compress payload via embedded Zstandard frame (zstd-19) for minimal disk footprint.
    EmbeddedZstd,
    /// Structure of Arrays physical storage layout.
    SoaLayout,
}

use crate::models::header::{RecordFamily, StorageLayout};

/// Optimization configuration representing chosen compiler transformation flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptimizationConfig {
    pub coalesce: bool,
    pub dedup_profiles: bool,
    pub normalize_strings: bool,
    pub lossy_coords: bool,
    pub prune_empty: bool,
    pub collapse_threats: bool,
    pub compact_ranges: bool,
    pub split64_v6: bool,
    pub embedded_zstd: bool,
    pub layout: StorageLayout,
    pub family: RecordFamily,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        // -O1 is the default safe optimization configuration
        Self::level_1()
    }
}

impl OptimizationConfig {
    /// -O0: No optimizations (raw interval pass-through).
    pub fn level_0() -> Self {
        Self {
            coalesce: false,
            dedup_profiles: true,
            normalize_strings: false,
            lossy_coords: false,
            prune_empty: true,
            collapse_threats: false,
            compact_ranges: false,
            split64_v6: false,
            embedded_zstd: false,
            layout: StorageLayout::Aos,
            family: RecordFamily::Standard,
        }
    }

    /// -O1: Default safe lossless coalescing + profile deduplication + empty string pruning.
    pub fn level_1() -> Self {
        Self {
            coalesce: true,
            dedup_profiles: true,
            normalize_strings: false,
            lossy_coords: false,
            prune_empty: true,
            collapse_threats: false,
            compact_ranges: false,
            split64_v6: false,
            embedded_zstd: false,
            layout: StorageLayout::Aos,
            family: RecordFamily::Standard,
        }
    }

    /// -O2: -O1 + string normalization.
    pub fn level_2() -> Self {
        Self {
            coalesce: true,
            dedup_profiles: true,
            normalize_strings: true,
            lossy_coords: false,
            prune_empty: true,
            collapse_threats: false,
            compact_ranges: false,
            split64_v6: false,
            embedded_zstd: false,
            layout: StorageLayout::Aos,
            family: RecordFamily::Standard,
        }
    }

    /// -O3: -O2 + lossy coordinate quantization (maximum edge reduction).
    pub fn level_3() -> Self {
        Self {
            coalesce: true,
            dedup_profiles: true,
            normalize_strings: true,
            lossy_coords: true,
            prune_empty: true,
            collapse_threats: false,
            compact_ranges: false,
            split64_v6: false,
            embedded_zstd: false,
            layout: StorageLayout::Aos,
            family: RecordFamily::Standard,
        }
    }

    /// Parses optimization level or list of rules (e.g. "-O2", "O1", "coalesce,compact-ranges").
    pub fn parse_arg(&mut self, s: &str) -> Result<(), String> {
        let trimmed = s.trim();
        let stripped = trimmed
            .strip_prefix("-O")
            .or_else(|| trimmed.strip_prefix('O'))
            .unwrap_or(trimmed);

        match stripped {
            "0" => {
                *self = Self::level_0();
                return Ok(());
            }
            "1" => {
                *self = Self::level_1();
                return Ok(());
            }
            "2" => {
                *self = Self::level_2();
                return Ok(());
            }
            "3" => {
                *self = Self::level_3();
                return Ok(());
            }
            _ => {}
        }

        // Parse individual rules
        for item in stripped.split(',') {
            let rule = item.trim().to_lowercase();
            match rule.as_str() {
                "coalesce" => self.coalesce = true,
                "no-coalesce" => self.coalesce = false,
                "dedup" | "dedup-profiles" => self.dedup_profiles = true,
                "normalize-strings" | "norm-str" => self.normalize_strings = true,
                "lossy-coords" | "lossy" => self.lossy_coords = true,
                "split64-v6" | "split64" | "lossy-v6" => self.split64_v6 = true,
                "prune-empty" => self.prune_empty = true,
                "collapse-threats" => self.collapse_threats = true,
                "compact" | "compact-ranges" | "v4.1" | "v4-compact" => {
                    self.compact_ranges = true;
                    self.family = RecordFamily::Compact;
                }
                "standard" => {
                    self.compact_ranges = false;
                    self.family = RecordFamily::Standard;
                }
                "soa" | "structure-of-arrays" => self.layout = StorageLayout::Soa,
                "aos" | "array-of-structures" => self.layout = StorageLayout::Aos,
                "zstd" | "embedded-zstd" => self.embedded_zstd = true,
                other => return Err(format!("Unknown optimization rule or level: '{}'. Available: 0, 1, 2, 3, coalesce, normalize-strings, lossy-coords, split64-v6, prune-empty, collapse-threats, compact-ranges, soa, aos, embedded-zstd", other)),
            }
        }
        Ok(())
    }
}

/// Computes the optimal record count for a compressed chunk based on record byte size.
///
/// Designed to align with CPU L1/L2 cache line size (64 bytes) and L2 residency (target ~64 KB chunk size).
/// For 8-byte compact records: 8,192 records = 65,536 bytes (1,024 cache lines).
/// For 12-byte standard records: 5,461 records = 65,532 bytes.
/// For 36-byte IPv6 records: 1,820 records = 65,520 bytes.
#[inline(always)]
pub fn calculate_chunk_records_count(record_size: usize, target_chunk_bytes: usize) -> usize {
    if record_size == 0 {
        return 0;
    }
    // Align chunk capacity down to a multiple of whole structures
    (target_chunk_bytes / record_size).max(1)
}

/// Symmetrically quantizes fixed-point coordinates to nearest multiple of 10 (~10km) without zero-truncation bias.
#[inline(always)]
pub fn quantize_coordinate(val: i16) -> i16 {
    if val >= 0 {
        ((val + 5) / 10) * 10
    } else {
        ((val - 5) / 10) * 10
    }
}
