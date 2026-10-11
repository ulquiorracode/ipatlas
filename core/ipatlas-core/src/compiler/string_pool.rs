use std::collections::HashMap;

/// Deduplicating string pool with a 1-element Last-Value Cache (LVC).
///
/// Builds a contiguous null-terminated string table and offset array.
/// Since geographic and ISP blocks in sorted CSV files cluster together,
/// LVC absorbs 80-95% of queries without querying the inner HashMap.
#[derive(Default)]
pub struct StringPool {
    map: HashMap<String, u32>,
    pub offsets: Vec<u32>,
    pub blob: Vec<u8>,
    last_str: String,
    last_idx: u32,
}

impl StringPool {
    /// Creates a new string pool with index 0 reserved for the empty string.
    pub fn new() -> Self {
        let mut pool = Self {
            map: HashMap::new(),
            offsets: Vec::new(),
            blob: Vec::new(),
            last_str: String::new(),
            last_idx: 0,
        };
        // Index 0 is always the empty string
        pool.offsets.push(0);
        pool.blob.push(0);
        pool.map.insert(String::new(), 0);
        pool.map.insert("-".to_string(), 0);
        pool
    }

    /// Fast lookup and insertion with 1-element Last-Value Cache (LVC).
    #[inline]
    pub fn get_or_insert(&mut self, s: &str, prune_empty: bool) -> u32 {
        if prune_empty && (s.is_empty() || s == "-") {
            return 0;
        }
        if !self.last_str.is_empty() && s == self.last_str {
            return self.last_idx;
        }
        if let Some(&idx) = self.map.get(s) {
            self.last_str.clear();
            self.last_str.push_str(s);
            self.last_idx = idx;
            return idx;
        }
        let idx = self.offsets.len() as u32;
        let offset = self.blob.len() as u32;
        self.offsets.push(offset);
        self.blob.extend_from_slice(s.as_bytes());
        self.blob.push(0); // Null terminator
        self.map.insert(s.to_string(), idx);
        self.last_str.clear();
        self.last_str.push_str(s);
        self.last_idx = idx;
        idx
    }
}
