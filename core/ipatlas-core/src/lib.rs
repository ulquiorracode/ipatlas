pub mod models;
pub mod pipeline;
pub mod reader;

#[cfg(feature = "compiler")]
pub mod compiler;

pub use models::{
    calculate_chunk_records_count, quantize_coordinate, ContainerVersion, FeatureMask, GeoFlags,
    GeoRecord, GeoRecordRef, HeaderGen4, HeaderGen5, HeaderV4, HeaderV5, Ipv4Range,
    Ipv4RangeCompact, Ipv6Range, Ipv6RangeCompact, Ipv6RangeSplit64, OptRule, OptimizationConfig,
    Preset, Profile, ProfileGen4, ProfileV4, RangeV4, RangeV4Compact, RangeV6, RecordFamily,
    StorageLayout, HEADER_SIZE_GEN4, HEADER_SIZE_GEN5, HEADER_SIZE_V4, HEADER_SIZE_V5, MAGIC,
    PROFILE_SIZE_GEN4, PROFILE_SIZE_V4, RECORD_SIZE_IPV4_COMPACT, RECORD_SIZE_IPV4_STANDARD,
    RECORD_SIZE_IPV6_COMPACT, RECORD_SIZE_IPV6_STANDARD, RECORD_SIZE_V4_COMPACT,
    RECORD_SIZE_V4_STANDARD, RECORD_SIZE_V6, VERSION_V4_COMPACT, VERSION_V4_COMPACT_AOS,
    VERSION_V4_COMPACT_SOA, VERSION_V4_STANDARD, VERSION_V4_STANDARD_AOS, VERSION_V4_STANDARD_SOA,
    VERSION_V5_COMPACT, VERSION_V5_COMPACT_AOS, VERSION_V5_COMPACT_SOA, VERSION_V5_STANDARD,
    VERSION_V5_STANDARD_AOS, VERSION_V5_STANDARD_SOA,
};
pub use pipeline::{
    BogonFilterLayer, IpAtlasPipelineExt, IpAtlasTerminal, LookupContext, LookupError,
    LookupIntent, LookupOutcome, TelemetryLayer, ThreatPolicyLayer,
};
#[cfg(feature = "hot-reload")]
pub use reader::HotReloadDatabase;
pub use reader::{HeaderVariant, IpAtlasReader, ReaderError};

#[cfg(feature = "compiler")]
pub use compiler::{
    compile, compile_adapter, CompilationStats, CompilerError, CompilerOptions,
    DatasetIngestionAdapter, IngestRecordV4, IngestRecordV6,
};
