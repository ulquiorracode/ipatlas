use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use ipatlas::{compile, CompilerOptions, GeoFlags, IpAtlasReader, ReaderError};

#[test]
fn test_v5_dualstack_compilation_and_lookup() {
    let dir = tempdir().unwrap();

    // 1. IPv4 Geo & Proxy CSV
    let geo_v4 = dir.path().join("geo_v4.csv");
    let mut f = File::create(&geo_v4).unwrap();
    writeln!(f, "\"16777472\",\"16777727\",\"US\",\"United States\",\"California\",\"Los Angeles\",\"34.0522\",\"-118.2437\",\"Google LLC\",\"15169\"").unwrap();
    drop(f);

    let px_v4 = dir.path().join("px_v4.csv");
    let mut f = File::create(&px_v4).unwrap();
    writeln!(f, "\"16777472\",\"16777727\",\"VPN\",\"US\",\"United States\",\"California\",\"Los Angeles\",\"Google VPN\",\"15169\",\"SES\",\"SPAM\"").unwrap();
    drop(f);

    // 2. IPv6 Geo & Proxy CSV
    // Range 1: 2001:db8::1 to 2001:db8::1000
    // Range 2: 2607:f8b0:4005:800::/64
    let u128_from_1: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0001;
    let u128_to_1: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_1000;

    let u128_from_2: u128 = 0x2607_f8b0_4005_0800_0000_0000_0000_0000;
    let u128_to_2: u128 = 0x2607_f8b0_4005_0800_ffff_ffff_ffff_ffff;

    let geo_v6 = dir.path().join("geo_v6.csv");
    let mut f = File::create(&geo_v6).unwrap();
    writeln!(f, "\"{}\",\"{}\",\"DE\",\"Germany\",\"Hesse\",\"Frankfurt\",\"50.1109\",\"8.6821\",\"Hetrix\",\"24940\"", u128_from_1, u128_to_1).unwrap();
    writeln!(f, "\"{}\",\"{}\",\"US\",\"United States\",\"California\",\"Mountain View\",\"37.3861\",\"-122.0839\",\"Google Cloud\",\"15169\"", u128_from_2, u128_to_2).unwrap();
    drop(f);

    let px_v6 = dir.path().join("px_v6.csv");
    let mut f = File::create(&px_v6).unwrap();
    writeln!(f, "\"{}\",\"{}\",\"TOR\",\"DE\",\"Germany\",\"Hesse\",\"Frankfurt\",\"Hetrix TOR\",\"24940\",\"DCH\",\"BOTNET\"", u128_from_1, u128_to_1).unwrap();
    writeln!(f, "\"{}\",\"{}\",\"RES\",\"US\",\"United States\",\"California\",\"Mountain View\",\"Residential Net\",\"15169\",\"SES\",\"SCANNER\"", u128_from_2, u128_to_2).unwrap();
    drop(f);

    let out_bin = dir.path().join("dualstack_v5.bin");

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&geo_v4))
        .proxy(Some(&px_v4))
        .geo_v6(Some(&geo_v6))
        .proxy_v6(Some(&px_v6));

    let stats = compile(opts).expect("V5 dualstack compilation failed");
    assert_eq!(stats.records_v4, 1);
    assert_eq!(stats.records_v6, 2);
    assert_eq!(stats.records, 3);
    assert_ne!(stats.crc32, 0);

    // Read and verify database
    let reader = IpAtlasReader::open(&out_bin).expect("Failed to open compiled V5 database");
    assert_eq!(reader.version(), 5);
    assert_eq!(reader.len(), 3);
    assert_eq!(reader.len_v4(), 1);
    assert_eq!(reader.len_v6(), 2);
    assert_eq!(reader.crc32(), Some(stats.crc32));

    // Verify CRC32 validation succeeds
    assert!(reader.validate_checksum().is_ok());

    // 3. Test IPv4 Lookup
    let v4_rec = reader.lookup_str("1.0.1.5").expect("IPv4 lookup failed");
    assert!(!v4_rec.is_v6);
    assert_eq!(v4_rec.country, "US");
    assert_eq!(v4_rec.city, "Los Angeles");
    assert!(v4_rec.flags.is_vpn());
    assert!(v4_rec.flags.is_ses());
    assert!(v4_rec.flags.is_spam());

    // 4. Test IPv6 Lookups
    let v6_rec1 = reader
        .lookup_str("2001:db8::5")
        .expect("IPv6 lookup 1 failed");
    assert!(v6_rec1.is_v6);
    assert_eq!(v6_rec1.country, "DE");
    assert_eq!(v6_rec1.city, "Frankfurt");
    assert!(v6_rec1.flags.is_tor());
    assert!(v6_rec1.flags.is_datacenter());
    assert!(v6_rec1.flags.is_botnet());

    let v6_rec2 = reader
        .lookup_str("2607:f8b0:4005:800::cafe")
        .expect("IPv6 lookup 2 failed");
    assert!(v6_rec2.is_v6);
    assert_eq!(v6_rec2.country, "US");
    assert_eq!(v6_rec2.city, "Mountain View");
    assert!(v6_rec2.flags.is_res());
    assert!(v6_rec2.flags.is_ses());
    assert!(v6_rec2.flags.is_scanner());

    // Miss lookup
    assert!(reader.lookup_str("2001:db8::2000").is_none());
}

#[test]
fn test_v5_crc32_corruption_detection() {
    let dir = tempdir().unwrap();
    let geo_v4 = dir.path().join("geo.csv");
    let mut f = File::create(&geo_v4).unwrap();
    writeln!(f, "\"16777472\",\"16777727\",\"US\",\"United States\",\"California\",\"Los Angeles\",\"34.0522\",\"-118.2437\",\"Test\",\"100\"").unwrap();
    drop(f);

    let out_bin = dir.path().join("crc_test.bin");
    let opts = CompilerOptions::new(&out_bin).geo(Some(&geo_v4));
    compile(opts).unwrap();

    // Verify clean database passes checksum
    let reader = IpAtlasReader::open(&out_bin).unwrap();
    assert!(reader.validate_checksum().is_ok());
    drop(reader);

    // Corrupt one byte after header (> 80)
    let mut data = std::fs::read(&out_bin).unwrap();
    let corrupt_idx = 100;
    data[corrupt_idx] ^= 0xFF;
    std::fs::write(&out_bin, &data).unwrap();

    let reader_corrupt = IpAtlasReader::open(&out_bin).unwrap();
    let err = reader_corrupt.validate_checksum().unwrap_err();
    assert!(matches!(err, ReaderError::CrcMismatch { .. }));
}

#[test]
fn test_all_9_proxy_types_flags() {
    let mut f = GeoFlags::default();
    assert_eq!(f.0, 0);

    f.0 |= GeoFlags::VPN;
    assert!(f.is_vpn());

    f.0 |= GeoFlags::TOR;
    assert!(f.is_tor());

    f.0 |= GeoFlags::DCH;
    assert!(f.is_datacenter());

    f.0 |= GeoFlags::PUB;
    assert!(f.is_pub());
    assert!(f.is_public_proxy());

    f.0 |= GeoFlags::WEB;
    assert!(f.is_web());
    assert!(f.is_web_proxy());

    f.0 |= GeoFlags::SES;
    assert!(f.is_ses());
    assert!(f.is_search_spider());

    f.0 |= GeoFlags::RES;
    assert!(f.is_res());
    assert!(f.is_residential_proxy());

    f.0 |= GeoFlags::CPN;
    assert!(f.is_cpn());
    assert!(f.is_consumer_privacy_network());

    f.0 |= GeoFlags::EPN;
    assert!(f.is_epn());
    assert!(f.is_enterprise_private_network());

    assert!(f.is_proxy());
}

#[test]
fn test_legacy_v4_flags_conversion() {
    // Legacy V4: DATACENTER (0x0001) and PROXY (0x0800)
    let v4_datacenter = GeoFlags::from_v4(0x0001);
    assert!(v4_datacenter.is_datacenter());
    assert!(!v4_datacenter.is_vpn());

    let v4_proxy = GeoFlags::from_v4(0x0800);
    assert!(v4_proxy.is_proxy());
    assert!(!v4_proxy.is_botnet());

    // Legacy V4: BOTNET (0x0400) and SPAM (0x0100)
    let v4_threats = GeoFlags::from_v4(0x0400 | 0x0100);
    assert!(v4_threats.is_botnet());
    assert!(v4_threats.is_spam());
    assert!(!v4_threats.is_proxy());
}

#[test]
fn test_v5_ipv6_split64_compact_compilation_and_lookup() {
    let dir = tempdir().unwrap();

    let u128_from_1: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0000;
    let u128_to_1: u128 = 0x2001_0db8_0000_0000_ffff_ffff_ffff_ffff; // /64

    let u128_from_2: u128 = 0x2607_f8b0_4005_0800_0000_0000_0000_0000;
    let u128_to_2: u128 = 0x2607_f8b0_4005_0803_ffff_ffff_ffff_ffff; // 4 * /64

    let geo_v6 = dir.path().join("geo_v6.csv");
    let mut f = File::create(&geo_v6).unwrap();
    writeln!(
        f,
        "\"{}\",\"{}\",\"DE\",\"Germany\",\"Hesse\",\"Frankfurt\",\"50.1109\",\"8.6821\",\"Hetrix\",\"24940\"",
        u128_from_1, u128_to_1
    )
    .unwrap();
    writeln!(
        f,
        "\"{}\",\"{}\",\"US\",\"United States\",\"California\",\"Mountain View\",\"37.3861\",\"-122.0839\",\"Google Cloud\",\"15169\"",
        u128_from_2, u128_to_2
    )
    .unwrap();
    drop(f);

    let px_v6 = dir.path().join("px_v6.csv");
    let mut f = File::create(&px_v6).unwrap();
    writeln!(
        f,
        "\"{}\",\"{}\",\"TOR\",\"DE\",\"Germany\",\"Hesse\",\"Frankfurt\",\"Hetrix TOR\",\"domain.com\",\"DCH\",\"24940\",\"AS_HETRIX\",\"2026-01-01\",\"BOTNET\"",
        u128_from_1, u128_to_1
    )
    .unwrap();
    drop(f);

    let out_compact_bin = dir.path().join("dualstack_compact_v5.bin");

    // Compile with Compact family and explicit Split64 IPv6 opt-in
    let opt = ipatlas::OptimizationConfig {
        family: ipatlas::RecordFamily::Compact,
        split64_v6: true,
        ..Default::default()
    };

    let opts = CompilerOptions::new(&out_compact_bin)
        .geo_v6(Some(&geo_v6))
        .proxy_v6(Some(&px_v6))
        .optimization(opt);

    let stats = compile(opts).expect("V5 compact dualstack compilation failed");
    assert_eq!(stats.records_v6, 2);

    let reader =
        IpAtlasReader::open(&out_compact_bin).expect("Failed to open compiled compact V5 database");
    assert_eq!(reader.len_v6(), 2);
    assert_eq!(reader.ranges_v6_compact().len(), 2);
    assert_eq!(reader.ranges_v6().len(), 0); // Standard ranges are empty in compact mode

    // Check Split-64 record properties
    let r1 = &reader.ranges_v6_compact()[0];
    assert_eq!(r1.ip_from_hi, (u128_from_1 >> 64) as u64);
    assert_eq!(r1.count_hi, 0); // 1 /64 subnet (from_hi == to_hi)

    let r2 = &reader.ranges_v6_compact()[1];
    assert_eq!(r2.ip_from_hi, (u128_from_2 >> 64) as u64);
    assert_eq!(r2.count_hi, 3); // 4 /64 subnets (difference of 3)

    // Verify lookup_u128 on compact split-64
    let rec1 = reader
        .lookup_u128(u128_from_1 + 0x1234_5678)
        .expect("Failed to lookup IPv6 in subnet 1");
    assert_eq!(rec1.country, "DE");
    assert_eq!(rec1.city, "Frankfurt");

    let rec2 = reader
        .lookup_u128(u128_to_2 - 0x10)
        .expect("Failed to lookup IPv6 in subnet 2");
    assert_eq!(rec2.country, "US");
    assert_eq!(rec2.city, "Mountain View");

    // Verify fast-paths on compact split-64
    let prof = reader
        .lookup_profile_u128(u128_from_1 + 0x55)
        .expect("Profile lookup failed");
    assert_eq!(prof.country_code(), "DE");
    assert_eq!(prof.asn, 24940);
}

#[test]
fn test_ipv6_sub_slash64_over_approximation_contract() {
    let dir = tempdir().unwrap();

    // Define a sub-/64 range: 2001:db8::10 to 2001:db8::20 (within 2001:db8::0/64)
    let sub_from: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0010;
    let sub_to: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0020;

    let geo_v6 = dir.path().join("sub64_geo.csv");
    let mut f = File::create(&geo_v6).unwrap();
    writeln!(
        f,
        "\"{}\",\"{}\",\"FR\",\"France\",\"IDF\",\"Paris\",\"48.8566\",\"2.3522\",\"OVH\",\"16276\"",
        sub_from, sub_to
    )
    .unwrap();
    drop(f);

    // 1. Standard (Lossless default) Mode:
    // Even under Compact family (which compacts IPv4), IPv6 remains lossless Standard 36B by default!
    let std_bin = dir.path().join("sub64_std.bin");
    let opt_default = ipatlas::OptimizationConfig {
        family: ipatlas::RecordFamily::Compact,
        split64_v6: false, // default safe lossless mode
        ..Default::default()
    };
    compile(
        CompilerOptions::new(&std_bin)
            .geo_v6(Some(&geo_v6))
            .optimization(opt_default),
    )
    .expect("Standard compilation failed");

    let reader_std = IpAtlasReader::open(&std_bin).unwrap();
    assert_eq!(reader_std.ranges_v6().len(), 1);
    assert_eq!(reader_std.ranges_v6_compact().len(), 0);

    // Inside sub-range: Hit
    assert!(reader_std.lookup_u128(sub_from).is_some());
    assert!(reader_std.lookup_u128(sub_from + 5).is_some());
    assert!(reader_std.lookup_u128(sub_to).is_some());
    // Outside sub-range within the same /64: Miss (lossless precision maintained!)
    assert!(reader_std
        .lookup_u128(0x2001_0db8_0000_0000_0000_0000_0000_0000)
        .is_none());
    assert!(reader_std
        .lookup_u128(0x2001_0db8_0000_0000_0000_0000_0000_0009)
        .is_none());
    assert!(reader_std
        .lookup_u128(0x2001_0db8_0000_0000_0000_0000_0000_0021)
        .is_none());
    assert!(reader_std
        .lookup_u128(0x2001_0db8_0000_0000_ffff_ffff_ffff_ffff)
        .is_none());

    // 2. Opt-in Split-64 (Lossy over-approximation) Mode:
    let split_bin = dir.path().join("sub64_split.bin");
    let opt_split64 = ipatlas::OptimizationConfig {
        family: ipatlas::RecordFamily::Compact,
        split64_v6: true, // explicit opt-in
        ..Default::default()
    };
    compile(
        CompilerOptions::new(&split_bin)
            .geo_v6(Some(&geo_v6))
            .optimization(opt_split64),
    )
    .expect("Split64 compilation failed");

    let reader_split = IpAtlasReader::open(&split_bin).unwrap();
    assert_eq!(reader_split.ranges_v6_compact().len(), 1);
    assert_eq!(reader_split.ranges_v6().len(), 0);

    // Contract: Split-64 drops the lower 64 bits and over-approximates the entire /64!
    // Inside sub-range: Hit
    assert!(reader_split.lookup_u128(sub_from + 5).is_some());
    // Boundary and outside sub-range within the /64: Hits due to over-approximation contract!
    assert!(reader_split
        .lookup_u128(0x2001_0db8_0000_0000_0000_0000_0000_0000)
        .is_some());
    assert!(reader_split
        .lookup_u128(0x2001_0db8_0000_0000_0000_0000_0000_0009)
        .is_some());
    assert!(reader_split
        .lookup_u128(0x2001_0db8_0000_0000_0000_0000_0000_0021)
        .is_some());
    assert!(reader_split
        .lookup_u128(0x2001_0db8_0000_0000_ffff_ffff_ffff_ffff)
        .is_some());
    // Different /64 prefix: Miss
    assert!(reader_split
        .lookup_u128(0x2001_0db8_0000_0001_0000_0000_0000_0000)
        .is_none());
}
