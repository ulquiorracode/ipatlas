use thiserror::Error;

/// Error types emitted during database reading, validation, and decompression.
#[derive(Error, Debug)]
pub enum ReaderError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database file is too small: {0} bytes")]
    FileTooSmall(u64),
    #[error("Corrupted database: {0}")]
    Corrupted(&'static str),
    #[error("CRC32 mismatch: expected {expected:#010x}, calculated {actual:#010x}")]
    CrcMismatch { expected: u32, actual: u32 },
    #[error("Unsupported database version: {0:#06x}")]
    UnsupportedVersion(u16),
    #[error("Decompression error: {0}")]
    Decompression(String),
}
