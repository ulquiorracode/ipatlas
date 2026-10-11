use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use ipatlas_core::{compile, CompilerOptions, IpAtlasReader};

#[test]
fn test_aot_footer_zero_copy_roundtrip() {
    let dir = tempdir().unwrap();
    let csv_path = dir.path().join("ranges.csv");
    let bin_path = dir.path().join("with_footer.bin");

    let mut f = File::create(&csv_path).unwrap();
    writeln!(f, "16777216,16777471,US,United States,CA,LA,34.05,-118.24").unwrap();
    writeln!(f, "33554432,33554687,DE,Germany,BE,Berlin,52.52,13.40").unwrap();
    drop(f);

    compile(CompilerOptions::new(&bin_path).geo(Some(&csv_path))).unwrap();

    let reader = IpAtlasReader::open(&bin_path).expect("Failed to open compiled database");
    assert!(
        reader.has_footer(),
        "Compiled database must have AOT Distribution Footer"
    );
    let footer = reader.footer().expect("Footer descriptor must be present");
    assert!(footer.has_guide_v4());
    assert_eq!(footer.guide_len(), 524288);
    assert!(
        footer.guide_offset() % 8 == 0,
        "Guide table offset must be 8-byte aligned"
    );

    // Verify lookup correctness
    let rec1 = reader.lookup_u32(16777220).expect("Record 1 not found");
    assert_eq!(rec1.country, "US");
    let rec2 = reader.lookup_u32(33554440).expect("Record 2 not found");
    assert_eq!(rec2.country, "DE");
    assert!(reader.lookup_u32(8).is_none());

    // Verify CRC32 validation
    assert!(reader.validate_checksum().is_ok());
}

#[test]
fn test_legacy_file_without_footer_backward_compatibility() {
    let dir = tempdir().unwrap();
    let csv_path = dir.path().join("ranges.csv");
    let bin_with_footer = dir.path().join("with_footer.bin");
    let bin_stripped = dir.path().join("stripped_legacy.bin");

    let mut f = File::create(&csv_path).unwrap();
    writeln!(f, "16777216,16777471,US,United States,CA,LA,34.05,-118.24").unwrap();
    drop(f);

    compile(CompilerOptions::new(&bin_with_footer).geo(Some(&csv_path))).unwrap();

    let mut data = std::fs::read(&bin_with_footer).unwrap();
    // Strip the footer (last 512KB + align pad + 32-byte descriptor)
    let reader_orig = IpAtlasReader::open(&bin_with_footer).unwrap();
    let footer = reader_orig.footer().unwrap();
    let payload_len = footer.guide_offset() as usize;
    drop(reader_orig);

    data.truncate(payload_len);
    std::fs::write(&bin_stripped, &data).unwrap();

    // Opening stripped legacy container must succeed via fallback runtime generation
    let legacy_reader =
        IpAtlasReader::open(&bin_stripped).expect("Legacy container must open cleanly");
    assert!(
        !legacy_reader.has_footer(),
        "Stripped container should have no footer"
    );
    assert!(legacy_reader.footer().is_none());

    // Check lookup works identically
    let rec = legacy_reader
        .lookup_u32(16777220)
        .expect("Record must be found in legacy reader");
    assert_eq!(rec.country, "US");
    assert!(legacy_reader.validate_checksum().is_ok());
}
