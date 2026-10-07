use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use ipatlas_core::compiler::eytzinger::EytzingerSearch;
use ipatlas_core::{compile, CompilerOptions, IpAtlasReader, Ipv4RangeCompact, Ipv6RangeSplit64};

#[test]
fn test_fuzz_truncated_binaries_all_sizes() {
    let dir = tempdir().unwrap();
    let noise_file = dir.path().join("trunc_noise.bin");

    // Test every single size from 0 bytes up to 100 bytes
    for size in 0..=100 {
        let data = vec![0x41u8; size];
        let mut f = File::create(&noise_file).unwrap();
        f.write_all(&data).unwrap();
        drop(f);

        let res = std::panic::catch_unwind(|| {
            let _ = IpAtlasReader::open(&noise_file);
        });
        assert!(res.is_ok(), "Panic on size {size}!");
    }
}

#[test]
fn test_fuzz_corrupted_offsets_no_panic() {
    let dir = tempdir().unwrap();
    let csv_path = dir.path().join("base.csv");
    let bin_path = dir.path().join("base.bin");

    std::fs::write(
        &csv_path,
        "16777216,16777471,US,United States,CA,LA,34.05,-118.24\n",
    )
    .unwrap();
    compile(CompilerOptions::new(&bin_path).geo(Some(&csv_path))).unwrap();

    let original = std::fs::read(&bin_path).unwrap();

    // Systematically overwrite u32 values in header with extreme values (u32::MAX, u32::MAX - 1, 0)
    for offset in (4..80).step_by(4) {
        if offset + 4 > original.len() {
            break;
        }
        for bad_val in [0u32, 0xFFFF_FFFF, 0x8000_0000, 0x7FFF_FFFF, 1] {
            let mut corrupted = original.clone();
            corrupted[offset..offset + 4].copy_from_slice(&bad_val.to_le_bytes());

            let c_path = dir.path().join(format!("c_{offset}_{bad_val}.bin"));
            std::fs::write(&c_path, &corrupted).unwrap();

            let res = std::panic::catch_unwind(|| {
                if let Ok(reader) = IpAtlasReader::open(&c_path) {
                    let _ = reader.lookup_u32(16777220);
                    let _ = reader.try_lookup_u32(16777220);
                }
            });
            assert!(res.is_ok(), "Panic with offset {offset} = {bad_val}");
        }
    }
}

#[test]
fn test_eytzinger_adversarial_queries() {
    // 1. Single element
    let sorted_v4 = vec![Ipv4RangeCompact::new(100, 50, 1)];
    let mut ey_v4 = vec![Ipv4RangeCompact::default(); sorted_v4.len() + 1];
    EytzingerSearch::build_eytzinger(&sorted_v4, &mut ey_v4);

    assert!(EytzingerSearch::search_v4_compact(&ey_v4, 0).is_none());
    assert!(EytzingerSearch::search_v4_compact(&ey_v4, 99).is_none());
    assert!(EytzingerSearch::search_v4_compact(&ey_v4, 100).is_some());
    assert!(EytzingerSearch::search_v4_compact(&ey_v4, 125).is_some());
    assert!(EytzingerSearch::search_v4_compact(&ey_v4, 150).is_some());
    assert!(EytzingerSearch::search_v4_compact(&ey_v4, 151).is_none());
    assert!(EytzingerSearch::search_v4_compact(&ey_v4, u32::MAX).is_none());

    // 2. IPv6 Split64 single element
    let sorted_v6 = vec![Ipv6RangeSplit64::new(100, 50, 1)];
    let mut ey_v6 = vec![Ipv6RangeSplit64::default(); sorted_v6.len() + 1];
    EytzingerSearch::build_eytzinger(&sorted_v6, &mut ey_v6);

    assert!(EytzingerSearch::search_v6_split64(&ey_v6, 0).is_none());
    assert!(EytzingerSearch::search_v6_split64(&ey_v6, 125).is_some());
    assert!(EytzingerSearch::search_v6_split64(&ey_v6, u64::MAX).is_none());
}
