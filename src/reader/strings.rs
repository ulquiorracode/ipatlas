use crate::reader::error::ReaderError;

/// Zero-copy descriptor for length-prefixed UTF-8 string tables (cities, regions, ISPs).
#[derive(Clone, Copy, Debug)]
pub(crate) struct StringTableRef {
    pub(crate) count: usize,
    pub(crate) idx_start: usize,
    pub(crate) data_start: usize,
    pub(crate) data_len: usize,
}

impl StringTableRef {
    #[inline(always)]
    pub(crate) fn try_resolve<'a>(
        &self,
        buf: &'a [u8],
        idx: usize,
    ) -> Result<&'a str, ReaderError> {
        if idx >= self.count {
            return Err(ReaderError::Corrupted("String index exceeds table count"));
        }
        let pos = self.idx_start + idx * 4;
        if pos + 4 > buf.len() {
            return Err(ReaderError::Corrupted(
                "String offset table extends beyond buffer",
            ));
        }
        let off = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;

        let d_end = self.data_start + self.data_len;
        if d_end > buf.len() {
            return Err(ReaderError::Corrupted(
                "String data blob extends beyond buffer",
            ));
        }
        let blob = &buf[self.data_start..d_end];
        if off >= blob.len() {
            return Err(ReaderError::Corrupted(
                "String offset out of bounds of blob",
            ));
        }
        let slice = &blob[off..];
        let len = memchr::memchr(0, slice).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..len])
            .map_err(|_| ReaderError::Corrupted("Invalid UTF-8 sequence in string table"))
    }

    #[inline(always)]
    pub(crate) fn resolve<'a>(&self, buf: &'a [u8], idx: usize) -> &'a str {
        self.try_resolve(buf, idx).unwrap_or("")
    }
}
