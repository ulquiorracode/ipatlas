pub mod parser;
pub mod sweep;
pub mod writer;

use std::path::Path;
use thiserror::Error;

use crate::compiler::parser::{stream_geo_file, stream_px_file, RawGeoRecord, RawPxRecord};
use crate::compiler::sweep::SweepLineMerger;
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
    pub output_path: &'a Path,
    pub features: FeatureMask,
    pub opt: OptimizationConfig,
    pub write_gz: bool,
    pub write_zst: bool,
}

impl<'a> CompilerOptions<'a> {
    pub fn new(output_path: &'a Path) -> Self {
        Self {
            geo_path: None,
            proxy_path: None,
            output_path,
            features: FeatureMask::default(),
            opt: OptimizationConfig::default(),
            write_gz: true,
            write_zst: true,
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

    pub fn geo(mut self, path: Option<&'a Path>) -> Self {
        self.geo_path = path;
        self
    }

    pub fn proxy(mut self, path: Option<&'a Path>) -> Self {
        self.proxy_path = path;
        self
    }

    pub fn compression(mut self, write_gz: bool, write_zst: bool) -> Self {
        self.write_gz = write_gz;
        self.write_zst = write_zst;
        self
    }
}

/// Compiles GeoIP and Proxy CSV datasets into an IPAtlas binary database.
pub fn compile(options: CompilerOptions<'_>) -> Result<CompilationStats, CompilerError> {
    if options.geo_path.is_none() && options.proxy_path.is_none() {
        return Err(CompilerError::NoInputFiles);
    }

    let geo_iter: Box<dyn Iterator<Item = RawGeoRecord>> = match options.geo_path {
        Some(p) => Box::new(stream_geo_file(p, options.features)?),
        None => Box::new(std::iter::empty()),
    };

    let px_iter: Box<dyn Iterator<Item = RawPxRecord>> = match options.proxy_path {
        Some(p) => Box::new(stream_px_file(p, options.features)?),
        None => Box::new(std::iter::empty()),
    };

    let merger = SweepLineMerger::new(geo_iter, px_iter, options.features, options.opt.clone());

    let mut writer = DatabaseWriter::new(options.opt);
    writer.ingest_all(merger);

    let stats = writer.write_to_file(options.output_path, options.write_gz, options.write_zst)?;
    Ok(stats)
}
