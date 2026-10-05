use memmap2::Mmap;

/// Backing storage for zero-copy views: either a zero-copy memory mapping or an in-memory buffer.
pub enum StorageBuffer {
    Mmap(Mmap),
    Memory(Vec<u8>),
}

impl std::ops::Deref for StorageBuffer {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &[u8] {
        match self {
            Self::Mmap(m) => m,
            Self::Memory(v) => v,
        }
    }
}
