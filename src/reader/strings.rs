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
    pub(crate) fn resolve<'a>(&self, buf: &'a [u8], idx: usize) -> &'a str {
        if idx >= self.count {
            return "";
        }
        let pos = self.idx_start + idx * 4;
        if pos + 4 > buf.len() {
            return "";
        }
        let off = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;

        let d_end = self.data_start + self.data_len;
        if d_end > buf.len() {
            return "";
        }
        let blob = &buf[self.data_start..d_end];
        if off >= blob.len() {
            return "";
        }
        let slice = &blob[off..];
        let len = memchr::memchr(0, slice).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..len]).unwrap_or("")
    }
}
