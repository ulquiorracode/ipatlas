/// Fine-grained optimization rules for database transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OptRule {
    /// Merge adjacent intervals [A, B] and [B+1, C] with identical feature profiles.
    Coalesce,
    /// Pool identical metadata tuples into normalized Profile IDs (V4).
    DedupProfiles,
    /// Trim whitespace and deduplicate string entries case-sensitively.
    NormalizeStrings,
    /// Quantize coordinates to 1 decimal place (~10km) to maximize coalescing and profile reuse.
    LossyCoords,
    /// Prune empty/dash string entries so they reference index 0.
    PruneEmpty,
    /// Strip sub-category threat flags, collapsing into generic proxy flag.
    CollapseThreats,
}

/// Optimization configuration representing chosen compiler transformation flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptimizationConfig {
    pub coalesce: bool,
    pub dedup_profiles: bool,
    pub normalize_strings: bool,
    pub lossy_coords: bool,
    pub prune_empty: bool,
    pub collapse_threats: bool,
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
        }
    }

    /// -O3: -O2 + lossy coordinate quantization (maximum edge compression).
    pub fn level_3() -> Self {
        Self {
            coalesce: true,
            dedup_profiles: true,
            normalize_strings: true,
            lossy_coords: true,
            prune_empty: true,
            collapse_threats: false,
        }
    }

    /// Parses optimization level or list of rules (e.g. "-O2", "O1", "coalesce,lossy-coords").
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
                "prune-empty" => self.prune_empty = true,
                "collapse-threats" => self.collapse_threats = true,
                other => return Err(format!("Unknown optimization rule or level: '{}'. Available: 0, 1, 2, 3, coalesce, normalize-strings, lossy-coords, prune-empty, collapse-threats", other)),
            }
        }
        Ok(())
    }
}
