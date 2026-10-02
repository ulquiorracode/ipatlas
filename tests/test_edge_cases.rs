use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use tempfile::tempdir;

use ipatlas::{compile, CompilerOptions, IpAtlasReader, ReaderError};

fn ip_to_u32(s: &str) -> u32 {
    let ip: Ipv4Addr = s.parse().unwrap();
    u32::from(ip)
}

#[test]
fn test_extreme_ipv4_boundaries() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("edge_db.csv");
    let out_bin = dir.path().join("boundary.bin");

    let db_content = format!(
        "{},{},ZZ,Zero Net,Zero,Zero,0.0,0.0\n\
         {},{},US,United States,CA,LA,34.0,-118.0\n\
         {},{},BC,Broadcast Net,End,End,90.0,0.0\n",
        ip_to_u32("0.0.0.0"),
        ip_to_u32("0.0.0.255"),
        ip_to_u32("10.0.0.100"),
        ip_to_u32("10.0.0.200"),
        ip_to_u32("255.255.255.0"),
        ip_to_u32("255.255.255.255")
    );
    let mut f = File::create(&db_path).unwrap();
    f.write_all(db_content.as_bytes()).unwrap();

    let opts = CompilerOptions::new(&out_bin).geo(Some(&db_path));
    compile(opts).unwrap();

    let reader = IpAtlasReader::open(&out_bin).unwrap();

    // 0.0.0.0 exact start
    let r0 = reader.lookup_str("0.0.0.0").expect("0.0.0.0 not found");
    assert_eq!(r0.country, "ZZ");

    // 0.0.0.255 exact end of interval
    let r0_end = reader.lookup_str("0.0.0.255").expect("0.0.0.255 not found");
    assert_eq!(r0_end.country, "ZZ");

    // 0.0.1.0 gap outside
    assert!(reader.lookup_str("0.0.1.0").is_none());

    // Middle interval exact boundaries
    assert!(reader.lookup_str("10.0.0.99").is_none());
    assert!(reader.lookup_str("10.0.0.100").is_some());
    assert!(reader.lookup_str("10.0.0.200").is_some());
    assert!(reader.lookup_str("10.0.0.201").is_none());

    // 255.255.255.255 exact end of 32-bit integer space
    assert!(reader.lookup_str("255.255.254.255").is_none());
    assert!(reader.lookup_str("255.255.255.0").is_some());
    let r_last = reader
        .lookup_str("255.255.255.255")
        .expect("255.255.255.255 not found");
    assert_eq!(r_last.country, "BC");
}

#[test]
fn test_corrupted_header_handling() {
    let dir = tempdir().unwrap();

    // 1. Empty file
    let empty_bin = dir.path().join("empty.bin");
    File::create(&empty_bin).unwrap();
    let res = IpAtlasReader::open(&empty_bin);
    assert!(matches!(res, Err(ReaderError::FileTooSmall(_))));

    // 2. Invalid magic header
    let bad_magic_bin = dir.path().join("bad_magic.bin");
    let mut f = File::create(&bad_magic_bin).unwrap();
    f.write_all(b"BADMAGIC012345678901234567890123456789012345678901234567890123456789")
        .unwrap();
    let res2 = IpAtlasReader::open(&bad_magic_bin);
    assert!(matches!(res2, Err(ReaderError::Corrupted(_))));

    // 3. Truncated header (< 68 bytes)
    let trunc_bin = dir.path().join("trunc.bin");
    let mut f2 = File::create(&trunc_bin).unwrap();
    f2.write_all(b"ATLS\x04\x00\x00\x00").unwrap();
    let res3 = IpAtlasReader::open(&trunc_bin);
    assert!(matches!(res3, Err(ReaderError::FileTooSmall(_))));
}

#[test]
fn test_empty_csv_compilation() {
    let dir = tempdir().unwrap();
    let empty_csv = dir.path().join("empty.csv");
    File::create(&empty_csv).unwrap();

    let out_bin = dir.path().join("empty_db.bin");
    let opts = CompilerOptions::new(&out_bin).geo(Some(&empty_csv));
    let stats = compile(opts).unwrap();
    assert_eq!(stats.records, 0);

    let reader = IpAtlasReader::open(&out_bin).unwrap();
    assert_eq!(reader.len(), 0);
    assert!(reader.is_empty());
    assert!(reader.lookup_str("1.1.1.1").is_none());
    assert!(reader.lookup_str("0.0.0.0").is_none());
}
