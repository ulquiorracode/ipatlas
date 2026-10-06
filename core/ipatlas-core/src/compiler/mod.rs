pub mod adapters;
pub mod eytzinger;
pub mod parser;
pub mod spi;
pub mod succinct;
pub mod sweep;
pub mod writer;

pub use spi::{DatasetIngestionAdapter, IngestRecordV4, IngestRecordV6};

use std::path::Path;
use thiserror::Error;

use crate::compiler::parser::{
    stream_geo_file, stream_geo_file_v6, stream_px_file, stream_px_file_v6, RawGeoRecord,
    RawGeoRecordV6, RawPxRecord, RawPxRecordV6,
};
use crate::compiler::sweep::{SweepLineMerger, SweepLineMergerV6};
pub use crate::compiler::writer::{CompilationStats, DatabaseWriter, StringPool};
use crate::models::{FeatureMask, OptimizationConfig, Preset};

#[derive(Error, Debug)]
pub enum CompilerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Compilation requires at least --geo or --proxy dataset input")]
    NoInputFiles,
    #[error("Invalid arguments: {0}")]
    InvalidArgs(String),
}

/// High-level database compilation builder and runner.
pub struct CompilerOptions<'a> {
    pub geo_path: Option<&'a Path>,
    pub proxy_path: Option<&'a Path>,
    pub geo_v6_path: Option<&'a Path>,
    pub proxy_v6_path: Option<&'a Path>,
    pub output_path: &'a Path,
    pub features: FeatureMask,
    pub opt: OptimizationConfig,
}

impl<'a> CompilerOptions<'a> {
    pub fn new(output_path: &'a Path) -> Self {
        Self {
            geo_path: None,
            proxy_path: None,
            geo_v6_path: None,
            proxy_v6_path: None,
            output_path,
            features: FeatureMask::default(),
            opt: OptimizationConfig::default(),
        }
    }

    pub fn preset(mut self, preset: Preset) -> Self {
        self.features = preset.feature_mask();
        self
    }

    pub fn features(mut self, features: FeatureMask) -> Self {
        self.features = features;
        self
    }

    pub fn optimization(mut self, opt: OptimizationConfig) -> Self {
        self.opt = opt;
        self
    }

    pub fn embedded_zstd(mut self, enabled: bool) -> Self {
        self.opt.embedded_zstd = enabled;
        self
    }

    pub fn geo(mut self, path: Option<&'a Path>) -> Self {
        self.geo_path = path;
        self
    }

    pub fn proxy(mut self, path: Option<&'a Path>) -> Self {
        self.proxy_path = path;
        self
    }

    pub fn geo_v6(mut self, path: Option<&'a Path>) -> Self {
        self.geo_v6_path = path;
        self
    }

    pub fn proxy_v6(mut self, path: Option<&'a Path>) -> Self {
        self.proxy_v6_path = path;
        self
    }
}

/// Compiles GeoIP and Proxy CSV datasets into an IPAtlas Generation V5 binary database.
pub fn compile(options: CompilerOptions<'_>) -> Result<CompilationStats, CompilerError> {
    let has_v4 = options.geo_path.is_some() || options.proxy_path.is_some();
    let has_v6 = options.geo_v6_path.is_some() || options.proxy_v6_path.is_some();

    if !has_v4 && !has_v6 {
        return Err(CompilerError::NoInputFiles);
    }

    let mut cities = StringPool::new();
    let mut regions = StringPool::new();
    let mut isps = StringPool::new();
    let prune_empty = options.opt.prune_empty;

    let mut writer = DatabaseWriter::new(options.opt.clone());

    // 1. Process IPv4 streams if present
    if has_v4 {
        let geo_iter: Box<dyn Iterator<Item = RawGeoRecord>> = match options.geo_path {
            Some(p) => Box::new(stream_geo_file(
                p,
                options.features,
                &mut cities,
                &mut regions,
                prune_empty,
            )?),
            None => Box::new(std::iter::empty()),
        };

        let px_iter: Box<dyn Iterator<Item = RawPxRecord>> = match options.proxy_path {
            Some(p) => Box::new(stream_px_file(p, options.features, &mut isps, prune_empty)?),
            None => Box::new(std::iter::empty()),
        };

        let merger_v4 =
            SweepLineMerger::new(geo_iter, px_iter, options.features, options.opt.clone());
        writer.ingest_all(merger_v4);
    }

    // 2. Process IPv6 streams if present
    if has_v6 {
        let geo_v6_iter: Box<dyn Iterator<Item = RawGeoRecordV6>> = match options.geo_v6_path {
            Some(p) => Box::new(stream_geo_file_v6(
                p,
                options.features,
                &mut cities,
                &mut regions,
                prune_empty,
            )?),
            None => Box::new(std::iter::empty()),
        };

        let px_v6_iter: Box<dyn Iterator<Item = RawPxRecordV6>> = match options.proxy_v6_path {
            Some(p) => Box::new(stream_px_file_v6(
                p,
                options.features,
                &mut isps,
                prune_empty,
            )?),
            None => Box::new(std::iter::empty()),
        };

        let merger_v6 =
            SweepLineMergerV6::new(geo_v6_iter, px_v6_iter, options.features, options.opt);
        writer.ingest_all_v6(merger_v6);
    }

    writer.set_pools(cities, regions, isps);
    let stats = writer.write_to_file(options.output_path)?;
    Ok(stats)
}

/// Compiles records from an arbitrary [`DatasetIngestionAdapter`] into an IPAtlas Generation V5 binary database.
pub fn compile_adapter<A: DatasetIngestionAdapter>(
    mut adapter: A,
    output_path: &Path,
    opt: OptimizationConfig,
    features: FeatureMask,
) -> Result<CompilationStats, CompilerError> {
    let mut cities = StringPool::new();
    let mut regions = StringPool::new();
    let mut isps = StringPool::new();
    let prune_empty = opt.prune_empty;

    let mut writer = DatabaseWriter::new(opt.clone());

    let (mut geo_records, mut px_records): (Vec<RawGeoRecord>, Vec<RawPxRecord>) = adapter
        .parse_v4()
        .map(|rec| rec.into_raw_pair(&mut cities, &mut regions, &mut isps, prune_empty))
        .unzip();

    geo_records.sort_unstable_by_key(|r| r.ip_from);
    px_records.sort_unstable_by_key(|r| r.ip_from);

    let merger = SweepLineMerger::new(
        geo_records.into_iter(),
        px_records.into_iter(),
        features,
        opt,
    );
    writer.ingest_all(merger);

    writer.set_pools(cities, regions, isps);
    let stats = writer.write_to_file(output_path)?;
    Ok(stats)
}
