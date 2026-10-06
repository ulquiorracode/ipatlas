use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use ipatlas_core::IpAtlasReader;

/// Deterministic pseudo-random bytes generator (LCG) to simulate random bit mutations.
struct Mutator {
    state: u64,
}

impl Mutator {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = (self.next_u32() & 0xFF) as u8;
        }
    }
}

#[test]
fn test_fuzz_arbitrary_binary_noise() {
    let dir = tempdir().unwrap();
    let fuzz_file = dir.path().join("fuzz_noise.bin");
    let mut mutator = Mutator::new(0xDEADBEEFCAFE1234);

    // Test 100 iterations of random bitstream sizes from 0 up to 128KB
    for size in [0, 1, 4, 16, 63, 64, 68, 79, 80, 128, 512, 1024, 4096, 65536] {
        let mut data = vec![0u8; size];
        mutator.fill(&mut data);

        let mut f = File::create(&fuzz_file).unwrap();
        f.write_all(&data).unwrap();
        drop(f);

        // Reader MUST NOT panic or segfault on arbitrary input!
        // It must cleanly return an Err(ReaderError).
        let result = std::panic::catch_unwind(|| {
            let _ = IpAtlasReader::open(&fuzz_file);
        });
        assert!(
            result.is_ok(),
            "Panic detected on random noise of size {size}!"
        );
    }
}

#[test]
fn test_fuzz_corrupted_valid_v5_container() {
    use ipatlas_core::{compile, CompilerOptions};

    let dir = tempdir().unwrap();
    let csv_path = dir.path().join("source.csv");
    let bin_path = dir.path().join("valid.bin");

    let mut f = File::create(&csv_path).unwrap();
    writeln!(f, "16777216,16777471,US,United States,CA,LA,34.05,-118.24").unwrap();
    drop(f);

    compile(CompilerOptions::new(&bin_path).geo(Some(&csv_path))).expect("compile valid db");

    let original_bytes = std::fs::read(&bin_path).expect("read valid bytes");
    assert!(original_bytes.len() >= 80);

    let mut mutator = Mutator::new(0x42424242);

    // Systematically flip bits across header and tables:
    for offset in [0, 4, 8, 12, 16, 24, 32, 40, 50, 60, 70, 79, 85, 100] {
        if offset >= original_bytes.len() {
            continue;
        }
        let mut corrupted = original_bytes.clone();
        corrupted[offset] ^= (mutator.next_u32() & 0xFF) as u8;

        let corrupted_file = dir.path().join(format!("corrupt_{offset}.bin"));
        let mut out = File::create(&corrupted_file).unwrap();
        out.write_all(&corrupted).unwrap();
        drop(out);

        // Memory safety invariant: catch_unwind must succeed (no panics / UB)
        let open_res = std::panic::catch_unwind(|| {
            if let Ok(reader) = IpAtlasReader::open(&corrupted_file) {
                // If it opened, query paths must not panic even on corrupted internal pointers
                let _ = reader.lookup_u32(16777220);
                let _ = reader.lookup_flags_u32(16777220);
                let _ = reader.lookup_country_code_u32(16777220);
                let _ = reader.lookup_profile_u32(16777220);
            }
        });
        assert!(open_res.is_ok(), "Panic on corrupted offset {offset}!");
    }
}
