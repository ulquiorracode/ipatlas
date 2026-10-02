pub mod features;
pub mod header;
pub mod optimization;
pub mod presets;
pub mod profile;
pub mod range;
pub mod record;

pub use features::FeatureMask;
pub use header::{
    HeaderV4, HEADER_SIZE_V4, MAGIC, PROFILE_SIZE_V4, RECORD_SIZE_V4_COMPACT,
    RECORD_SIZE_V4_STANDARD, VERSION_V4_COMPACT, VERSION_V4_STANDARD,
};
pub use optimization::{quantize_coordinate, OptRule, OptimizationConfig};
pub use presets::Preset;
pub use profile::ProfileV4;
pub use range::{RangeV4, RangeV4Compact};
pub use record::{GeoFlags, GeoRecord, GeoRecordRef};
