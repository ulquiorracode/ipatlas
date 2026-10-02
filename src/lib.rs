pub mod models;
pub mod reader;

#[cfg(feature = "compiler")]
pub mod compiler;

pub use models::{
    FeatureMask, GeoFlags, GeoRecord, GeoRecordRef, HeaderV4, OptRule, OptimizationConfig, Preset,
    ProfileV4, RangeV4, HEADER_SIZE_V4, MAGIC, PROFILE_SIZE_V4, RECORD_SIZE_V4, VERSION_V4,
};
pub use reader::{IpAtlasReader, ReaderError};

#[cfg(feature = "compiler")]
pub use compiler::{compile, CompilationStats, CompilerError, CompilerOptions};
