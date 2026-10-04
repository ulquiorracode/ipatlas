pub mod models;
pub mod pipeline;
pub mod reader;

#[cfg(feature = "compiler")]
pub mod compiler;

pub use models::{
    quantize_coordinate, FeatureMask, GeoFlags, GeoRecord, GeoRecordRef, HeaderV4, HeaderV5,
    OptRule, OptimizationConfig, Preset, ProfileV4, RangeV4, RangeV4Compact, RangeV6,
    HEADER_SIZE_V4, HEADER_SIZE_V5, MAGIC, PROFILE_SIZE_V4, RECORD_SIZE_V4_COMPACT,
    RECORD_SIZE_V4_STANDARD, RECORD_SIZE_V6, VERSION_V4_COMPACT, VERSION_V4_STANDARD,
    VERSION_V5_COMPACT, VERSION_V5_STANDARD,
};
pub use pipeline::{
    BogonFilterLayer, IpAtlasPipelineExt, IpAtlasTerminal, LookupContext, LookupError,
    LookupIntent, LookupOutcome, TelemetryLayer, ThreatPolicyLayer,
};
pub use reader::{HeaderVariant, IpAtlasReader, ReaderError};

#[cfg(feature = "compiler")]
pub use compiler::{compile, CompilationStats, CompilerError, CompilerOptions};
