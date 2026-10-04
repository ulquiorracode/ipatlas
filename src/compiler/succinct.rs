//! Experimental Prototype: Succinct Elias-Fano compressed interval table.
//!
//! Encodes monotonic IP range boundaries into a compact bitvector with Elias-Fano
//! quasi-succinct representation, reaching ~100% of the Shannon Entropy limit.

use crate::models::{ProfileV4, RangeV4};

/// Quasi-succinct bit-packed Elias-Fano interval storage.
#[derive(Clone, Debug)]
pub struct SuccinctIntervalTable {
    pub count: usize,
    pub universe: u64,
    pub low_bits_width: u8,
    pub low_bits: Vec<u64>,
    pub high_bits: Vec<u64>,
    pub profile_indices: Vec<u16>,
    pub profiles: Vec<ProfileV4>,
}

impl SuccinctIntervalTable {
    /// Builds a succinct table from a sorted list of non-overlapping intervals.
    pub fn build(ranges: &[RangeV4], profiles: Vec<ProfileV4>) -> Self {
        let count = ranges.len();
        if count == 0 {
            return Self {
                count: 0,
                universe: 0,
                low_bits_width: 0,
                low_bits: Vec::new(),
                high_bits: Vec::new(),
                profile_indices: Vec::new(),
                profiles,
            };
        }

        // Universe size is 2^32 for IPv4
        let universe = 1u64 << 32;
        // Elias-Fano optimal low-bits width: floor(log2(universe / count))
        let low_bits_width = if count < universe as usize {
            let ratio = universe / (count as u64);
            (63 - ratio.leading_zeros()) as u8
        } else {
            0
        };

        let low_mask = (1u64 << low_bits_width) - 1;
        let total_low_bits = count * (low_bits_width as usize);
        let low_words = total_low_bits.div_ceil(64);
        let mut low_bits = vec![0u64; low_words.max(1)];

        // High bits require count 1s and (universe >> low_bits_width) 0s
        let max_high = (universe >> low_bits_width) as usize;
        let total_high_bits = count + max_high + 64;
        let high_words = total_high_bits.div_ceil(64);
        let mut high_bits = vec![0u64; high_words.max(1)];

        let mut profile_indices = Vec::with_capacity(count);

        for (i, r) in ranges.iter().enumerate() {
            let val = r.ip_from as u64;
            let low = val & low_mask;
            let high = (val >> low_bits_width) as usize;

            // Pack low bits
            let word_idx = (i * (low_bits_width as usize)) / 64;
            let bit_offset = (i * (low_bits_width as usize)) % 64;
            low_bits[word_idx] |= low << bit_offset;
            if bit_offset + (low_bits_width as usize) > 64 && word_idx + 1 < low_bits.len() {
                low_bits[word_idx + 1] |= low >> (64 - bit_offset);
            }

            // High bits: set 1 at position (high + i)
            let high_pos = high + i;
            let h_word = high_pos / 64;
            let h_offset = high_pos % 64;
            if h_word < high_bits.len() {
                high_bits[h_word] |= 1u64 << h_offset;
            }

            profile_indices.push(r.profile_id as u16);
        }

        Self {
            count,
            universe,
            low_bits_width,
            low_bits,
            high_bits,
            profile_indices,
            profiles,
        }
    }

    /// Total memory footprint of the compressed interval index in bytes.
    pub fn index_size_bytes(&self) -> usize {
        (self.low_bits.len() * 8) + (self.high_bits.len() * 8) + (self.profile_indices.len() * 2)
    }

    /// Access the base `ip_from` for element `i` via bit decoding.
    #[inline]
    pub fn get_ip_from(&self, i: usize) -> u32 {
        if i >= self.count {
            return u32::MAX;
        }

        // 1. Decode low bits
        let bit_idx = i * (self.low_bits_width as usize);
        let word_idx = bit_idx / 64;
        let bit_offset = bit_idx % 64;
        let low_mask = (1u64 << self.low_bits_width) - 1;

        let mut low = self.low_bits[word_idx] >> bit_offset;
        if bit_offset + (self.low_bits_width as usize) > 64 && word_idx + 1 < self.low_bits.len() {
            low |= self.low_bits[word_idx + 1] << (64 - bit_offset);
        }
        let low = low & low_mask;

        // 2. Decode high bits by scanning for the i-th set bit (select1)
        let mut ones_seen = 0;
        let mut high_val = 0;
        for (w_idx, &w) in self.high_bits.iter().enumerate() {
            let ones = w.count_ones() as usize;
            if ones_seen + ones > i {
                // The target bit is in this word
                for b in 0..64 {
                    if (w & (1u64 << b)) != 0 {
                        if ones_seen == i {
                            let pos = w_idx * 64 + b;
                            high_val = pos - i;
                            break;
                        }
                        ones_seen += 1;
                    }
                }
                break;
            }
            ones_seen += ones;
        }

        let val = (high_val as u64) << self.low_bits_width | low;
        val as u32
    }

    /// Binary search over succinct intervals.
    pub fn lookup(&self, ip: u32) -> Option<&ProfileV4> {
        if self.count == 0 {
            return None;
        }

        let mut low = 0;
        let mut high = self.count;

        while low < high {
            let mid = low + (high - low) / 2;
            let mid_ip = self.get_ip_from(mid);
            if mid_ip <= ip {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        if low > 0 {
            let candidate_idx = low - 1;
            let prof_id = self.profile_indices[candidate_idx] as usize;
            if prof_id < self.profiles.len() {
                return Some(&self.profiles[prof_id]);
            }
        }

        None
    }
}
