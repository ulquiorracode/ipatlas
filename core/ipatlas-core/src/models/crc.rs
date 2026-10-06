const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if (c & 1) != 0 {
                c = (c >> 1) ^ 0xEDB8_8320;
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Computes standard IEEE 802.3 CRC32 checksum.
#[derive(Clone, Copy, Debug)]
pub struct Crc32(u32);

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    #[inline]
    pub const fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let idx = ((self.0 ^ (byte as u32)) & 0xFF) as usize;
            self.0 = (self.0 >> 8) ^ CRC32_TABLE[idx];
        }
    }

    #[inline]
    pub fn finalize(self) -> u32 {
        !self.0
    }
}

#[inline]
pub fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(data);
    crc.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_standard_vector() {
        let input = b"123456789";
        let crc = compute_crc32(input);
        assert_eq!(crc, 0xCBF4_3926);
    }
}
