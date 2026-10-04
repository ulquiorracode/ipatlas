pub mod crc;
pub mod features;
pub mod header;
pub mod optimization;
pub mod presets;
pub mod profile;
pub mod range;
pub mod record;

pub use crc::{compute_crc32, Crc32};
pub use features::FeatureMask;
pub use header::{
    ContainerVersion, HeaderV4, HeaderV5, RecordFamily, StorageLayout, HEADER_FLAG_EMBEDDED_ZSTD,
    HEADER_SIZE_V4, HEADER_SIZE_V5, MAGIC, PROFILE_SIZE_V4, RECORD_SIZE_V4_COMPACT,
    RECORD_SIZE_V4_STANDARD, RECORD_SIZE_V6, VERSION_V4_COMPACT, VERSION_V4_COMPACT_AOS,
    VERSION_V4_COMPACT_SOA, VERSION_V4_STANDARD, VERSION_V4_STANDARD_AOS, VERSION_V4_STANDARD_SOA,
    VERSION_V5_COMPACT, VERSION_V5_COMPACT_AOS, VERSION_V5_COMPACT_SOA, VERSION_V5_STANDARD,
    VERSION_V5_STANDARD_AOS, VERSION_V5_STANDARD_SOA,
};
pub use optimization::{
    calculate_chunk_records_count, quantize_coordinate, OptRule, OptimizationConfig,
};
pub use presets::Preset;
pub use profile::ProfileV4;
pub use range::{RangeV4, RangeV4Compact, RangeV6};
pub use record::{GeoFlags, GeoRecord, GeoRecordRef};
