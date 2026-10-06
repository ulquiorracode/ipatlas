//! Zero-downtime, lock-free hot reloading database container.
//!
//! Powered by [`arc_swap::ArcSwap`], allowing concurrent reader threads
//! to query the active memory map with zero contention or synchronization overhead
//! while a background worker or file watcher replaces the database image atomically.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};

use crate::reader::error::ReaderError;
use crate::reader::mmap_reader::IpAtlasReader;

/// Lock-free, atomically swappable container for an [`IpAtlasReader`].
///
/// Under high query volume (e.g. 5M+ QPS across multi-threaded HTTP servers or proxy engines),
/// `HotReloadDatabase` allows replacing the active `.bin` database on disk with zero downtime,
/// zero mutex contention, and zero dropped packets. In-flight lookups finish safely against
/// their pinned generation, and subsequent queries instantly transition to the new binary.
#[derive(Debug)]
pub struct HotReloadDatabase {
    path: PathBuf,
    reader: ArcSwap<IpAtlasReader>,
}

impl HotReloadDatabase {
    /// Opens the initial database file at `path` using standard fast mmap mapping.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ReaderError> {
        let path_buf = path.as_ref().to_path_buf();
        let initial = Arc::new(IpAtlasReader::open(&path_buf)?);
        Ok(Self {
            path: path_buf,
            reader: ArcSwap::from(initial),
        })
    }

    /// Opens the initial database file at `path` and immediately verifies CRC32 checksums.
    pub fn open_verified<P: AsRef<Path>>(path: P) -> Result<Self, ReaderError> {
        let path_buf = path.as_ref().to_path_buf();
        let initial = Arc::new(IpAtlasReader::open_verified(&path_buf)?);
        Ok(Self {
            path: path_buf,
            reader: ArcSwap::from(initial),
        })
    }

    /// Loads the currently active [`IpAtlasReader`] instance.
    ///
    /// Returns a lightweight RAII guard. Reading through the returned guard
    /// executes directly against the mapped pages without locking.
    #[inline(always)]
    pub fn load(&self) -> Guard<Arc<IpAtlasReader>> {
        self.reader.load()
    }

    /// Clones the inner `Arc<IpAtlasReader>`.
    #[inline(always)]
    pub fn load_full(&self) -> Arc<IpAtlasReader> {
        self.reader.load_full()
    }

    /// Atomically reloads the database from its original on-disk path.
    ///
    /// Validates the new file before replacing the active instance. If opening
    /// or validating the new file fails, the previous database remains completely intact.
    pub fn reload(&self) -> Result<(), ReaderError> {
        self.reload_from(&self.path)
    }

    /// Atomically reloads the database from a specified path and verifies CRC32.
    pub fn reload_verified(&self) -> Result<(), ReaderError> {
        let new_reader = Arc::new(IpAtlasReader::open_verified(&self.path)?);
        self.reader.store(new_reader);
        Ok(())
    }

    /// Atomically swaps the active database with a newly opened file from `new_path`.
    pub fn reload_from<P: AsRef<Path>>(&self, new_path: P) -> Result<(), ReaderError> {
        let new_reader = Arc::new(IpAtlasReader::open(new_path)?);
        self.reader.store(new_reader);
        Ok(())
    }

    /// Returns the database file path associated with this container.
    pub fn path(&self) -> &Path {
        &self.path
    }
}
