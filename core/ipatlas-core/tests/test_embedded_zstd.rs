use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use ipatlas_core::{compile, CompilerOptions, IpAtlasReader};

#[test]
fn test_embedded_zstd_compilation_and_lookup() {
    let dir = tempdir().unwrap();

    // 1. Setup sample IPv4 & IPv6 CSV datasets
    let geo_v4 = dir.path().join("geo_v4.csv");
    let mut f = File::create(&geo_v4).unwrap();
    for i in 1..=50 {
        let ip_start = i * 1000;
        let ip_end = ip_start + 500;
        writeln!(
            f,
            "\"{}\",\"{}\",\"US\",\"United States\",\"California\",\"San Jose\",\"37.3382\",\"-121.8863\",\"DataCenter Provider {}\",\"12345\"",
            ip_start, ip_end, i
        ).unwrap();
    }
    drop(f);

    let px_v4 = dir.path().join("px_v4.csv");
    let mut f = File::create(&px_v4).unwrap();
    for i in 1..=50 {
        let ip_start = i * 1000;
        let ip_end = ip_start + 500;
        writeln!(
            f,
            "\"{}\",\"{}\",\"VPN\",\"US\",\"United States\",\"California\",\"San Jose\",\"SecureProxy {}\",\"12345\",\"DCH\",\"BOTNET\"",
            ip_start, ip_end, i
        ).unwrap();
    }
    drop(f);

    let uncompressed_bin = dir.path().join("db_uncompressed.bin");
    let compressed_bin = dir.path().join("db_embedded_zstd.bin");

    // 2. Compile uncompressed database
    let opts_uncomp = CompilerOptions::new(&uncompressed_bin)
        .geo(Some(&geo_v4))
        .proxy(Some(&px_v4));
    let stats_uncomp = compile(opts_uncomp).expect("Uncompressed compilation failed");

    // 3. Compile embedded-zstd database
    let opts_comp = CompilerOptions::new(&compressed_bin)
        .geo(Some(&geo_v4))
        .proxy(Some(&px_v4))
        .embedded_zstd(true);
    let stats_comp = compile(opts_comp).expect("Embedded zstd compilation failed");

    // Verify CRC matches uncompressed payload CRC
    assert_eq!(stats_comp.crc32, stats_uncomp.crc32);

    let uncomp_size = std::fs::metadata(&uncompressed_bin).unwrap().len();
    let comp_size = std::fs::metadata(&compressed_bin).unwrap().len();

    println!(
        "Embedded Zstd test: Uncompressed = {} bytes, Compressed = {} bytes (Ratio: {:.2}x)",
        uncomp_size,
        comp_size,
        uncomp_size as f64 / comp_size as f64
    );

    // Embedded zstd file should be strictly smaller on repetitive data
    assert!(comp_size < uncomp_size);

    // 4. Open and verify uncompressed reader
    let reader_uncomp = IpAtlasReader::open(&uncompressed_bin).expect("Open uncompressed failed");
    assert!(!reader_uncomp.is_embedded_zstd());
    reader_uncomp
        .validate_checksum()
        .expect("Uncompressed CRC validation failed");

    // 5. Open and verify embedded zstd reader
    let reader_comp = IpAtlasReader::open(&compressed_bin).expect("Open compressed failed");
    assert!(reader_comp.is_embedded_zstd());
    assert_eq!(reader_comp.len(), reader_uncomp.len());
    assert_eq!(reader_comp.profile_count(), reader_uncomp.profile_count());
    assert_eq!(reader_comp.city_count(), reader_uncomp.city_count());

    // CRC validation against decompressed buffer MUST succeed
    reader_comp
        .validate_checksum()
        .expect("Compressed CRC validation failed");

    // 6. Cross-verify lookup results between both databases
    for i in 1..=50 {
        let test_ip = i * 1000 + 250;
        let rec_uncomp = reader_uncomp.lookup_u32(test_ip).expect("Lookup uncomp");
        let rec_comp = reader_comp.lookup_u32(test_ip).expect("Lookup comp");

        assert_eq!(rec_comp.country, rec_uncomp.country);
        assert_eq!(rec_comp.city, rec_uncomp.city);
        assert_eq!(rec_comp.region, rec_uncomp.region);
        assert_eq!(rec_comp.isp, rec_uncomp.isp);
        assert_eq!(rec_comp.asn, rec_uncomp.asn);
        assert_eq!(rec_comp.flags, rec_uncomp.flags);
        assert_eq!(rec_comp.latitude, rec_uncomp.latitude);
        assert_eq!(rec_comp.longitude, rec_uncomp.longitude);
    }

    // Out-of-range IP
    assert!(reader_comp.lookup_u32(999_999).is_none());
}
