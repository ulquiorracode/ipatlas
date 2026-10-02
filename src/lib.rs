pub mod models;
pub mod reader;

#[cfg(feature = "compiler")]
pub mod compiler;

pub use models::{
    quantize_coordinate, FeatureMask, GeoFlags, GeoRecord, GeoRecordRef, HeaderV4, OptRule,
    OptimizationConfig, Preset, ProfileV4, RangeV4, RangeV4Compact, HEADER_SIZE_V4, MAGIC,
    PROFILE_SIZE_V4, RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD, VERSION_V4_COMPACT,
    VERSION_V4_STANDARD,
};
pub use reader::{IpAtlasReader, ReaderError};

#[cfg(feature = "compiler")]
pub use compiler::{compile, CompilationStats, CompilerError, CompilerOptions};
