pub mod buffer;
pub(crate) mod dispatch;
pub mod error;
pub mod mmap_reader;
pub(crate) mod strings;

pub use error::ReaderError;
pub use mmap_reader::{HeaderVariant, IpAtlasReader};
