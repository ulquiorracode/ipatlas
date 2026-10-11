pub mod crc;
pub mod features;
pub mod footer;
pub mod header;
pub mod optimization;
pub mod presets;
pub mod profile;
pub mod range;
pub mod record;

pub use crc::{compute_crc32, Crc32};
pub use features::FeatureMask;
pub use footer::{
    ContainerFooter, FOOTER_FLAG_BOGON_RLE, FOOTER_FLAG_GUIDE_V4, FOOTER_INDEX_SIZE, FOOTER_MAGIC,
};
pub use header::{
    ContainerVersion, HeaderGen4, HeaderGen5, HeaderV4, HeaderV5, RecordFamily, StorageLayout,
    HEADER_FLAG_EMBEDDED_ZSTD, HEADER_FLAG_SOA_V6, HEADER_SIZE_GEN4, HEADER_SIZE_GEN5,
    HEADER_SIZE_V4, HEADER_SIZE_V5, MAGIC, PROFILE_SIZE_GEN4, PROFILE_SIZE_V4,
    RECORD_SIZE_IPV4_COMPACT, RECORD_SIZE_IPV4_STANDARD, RECORD_SIZE_IPV6_COMPACT,
    RECORD_SIZE_IPV6_STANDARD, RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD, RECORD_SIZE_V6,
    VERSION_V4_COMPACT, VERSION_V4_COMPACT_AOS, VERSION_V4_COMPACT_SOA, VERSION_V4_STANDARD,
    VERSION_V4_STANDARD_AOS, VERSION_V4_STANDARD_SOA, VERSION_V5_COMPACT, VERSION_V5_COMPACT_AOS,
    VERSION_V5_COMPACT_SOA, VERSION_V5_STANDARD, VERSION_V5_STANDARD_AOS, VERSION_V5_STANDARD_SOA,
};
pub use optimization::{
    calculate_chunk_records_count, quantize_coordinate, OptRule, OptimizationConfig,
};
pub use presets::Preset;
pub use profile::{Profile, ProfileGen4, ProfileV4};
pub use range::{
    Ipv4Range, Ipv4RangeCompact, Ipv6Range, Ipv6RangeCompact, Ipv6RangeSplit64, RangeV4,
    RangeV4Compact, RangeV6,
};
pub use record::{GeoFlags, GeoRecord, GeoRecordRef};
