use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use ipatlas_core::{
    compile, CompilerOptions, IpAtlasReader, OptimizationConfig, RecordFamily, StorageLayout,
};

fn ip_to_u32(ip: &str) -> u32 {
    let octets: Vec<u32> = ip.split('.').map(|s| s.parse().unwrap()).collect();
    (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
}

#[test]
fn test_soa_compact_roundtrip_compilation_and_lookup() {
    let dir = tempdir().unwrap();
    let db5_path = dir.path().join("test_geo.csv");
    let px10_path = dir.path().join("test_px.csv");
    let out_bin = dir.path().join("test_soa_compact.bin");

    let db5_content = format!(
        "\"{}\",\"{}\",\"US\",\"United States\",\"California\",\"Los Angeles\",\"34.0522\",\"-118.2437\",\"90001\",\"-08:00\"\n\
         \"{}\",\"{}\",\"JP\",\"Japan\",\"Tokyo\",\"Tokyo\",\"35.6895\",\"139.6917\",\"100-0001\",\"+09:00\"\n",
        ip_to_u32("1.0.0.0"),
        ip_to_u32("1.0.15.255"),
        ip_to_u32("1.0.16.0"),
        ip_to_u32("1.0.31.255")
    );
    let mut f = File::create(&db5_path).unwrap();
    f.write_all(db5_content.as_bytes()).unwrap();

    // PX10: ip_from, ip_to, proxy_type, cc, country_name, region, city, isp, domain, usage_type, asn, as_name, last_seen, threat
    let px10_content = format!(
        "{},{},PUB,US,United States,California,Los Angeles,Google Cloud,google.com,DCH,15169,Google LLC,2026-09-01,SPAM\n",
        ip_to_u32("1.0.0.0"),
        ip_to_u32("1.0.7.255")
    );
    let mut f_px = File::create(&px10_path).unwrap();
    f_px.write_all(px10_content.as_bytes()).unwrap();

    let opt = OptimizationConfig {
        compact_ranges: true,
        family: RecordFamily::Compact,
        layout: StorageLayout::Soa,
        ..Default::default()
    };

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db5_path))
        .proxy(Some(&px10_path))
        .optimization(opt);

    let stats = compile(opts).unwrap();
    assert!(stats.is_compact);
    assert!(stats.is_soa);

    let reader = IpAtlasReader::open(&out_bin).unwrap();
    assert!(reader.is_soa());
    assert!(reader.is_compact());
    assert_eq!(reader.layout(), StorageLayout::Soa);
    assert_eq!(reader.family(), RecordFamily::Compact);
    assert_eq!(reader.version(), 0x0503);

    // Verify SoA slice columns access
    let ip_froms = reader.soa_ip_froms_v4();
    let counts = reader.soa_counts_v4();
    let prof_ids = reader.soa_profile_ids_compact_v4();
    assert_eq!(ip_froms.len(), reader.len_v4());
    assert_eq!(counts.len(), reader.len_v4());
    assert_eq!(prof_ids.len(), reader.len_v4());

    // 1. Look up first chunk (1.0.0.0 - 1.0.7.255: US, Proxy DCH)
    let rec1 = reader.lookup_str("1.0.2.15").expect("Target 1 not found");
    assert_eq!(rec1.country, "US");
    assert_eq!(rec1.city, "Los Angeles");
    assert!(rec1.flags.is_proxy());
    assert!(rec1.flags.is_datacenter());
    assert!(reader.is_threat_u32(ip_to_u32("1.0.2.15")));
    assert!(reader.is_proxy_u32(ip_to_u32("1.0.2.15")));
    assert_eq!(
        reader.lookup_country_code_u32(ip_to_u32("1.0.2.15")),
        Some("US")
    );

    // 2. Look up second chunk (1.0.8.0 - 1.0.15.255: US, non-proxy)
    let rec2 = reader.lookup_str("1.0.10.1").expect("Target 2 not found");
    assert_eq!(rec2.country, "US");
    assert!(!rec2.flags.is_proxy());
    assert!(!reader.is_threat_u32(ip_to_u32("1.0.10.1")));

    // 3. Look up JP chunk (1.0.16.0 - 1.0.31.255: JP)
    let rec3 = reader.lookup_str("1.0.20.100").expect("Target 3 not found");
    assert_eq!(rec3.country, "JP");
    assert_eq!(rec3.city, "Tokyo");
    assert_eq!(
        reader.lookup_country_code_u32(ip_to_u32("1.0.20.100")),
        Some("JP")
    );

    // 4. Look up out-of-bounds IP
    assert!(reader.lookup_str("2.0.0.1").is_none());
    assert_eq!(reader.lookup_country_code_u32(ip_to_u32("2.0.0.1")), None);
}

#[test]
fn test_soa_standard_roundtrip_compilation_and_lookup() {
    let dir = tempdir().unwrap();
    let db5_path = dir.path().join("test_geo_std.csv");
    let out_bin = dir.path().join("test_soa_standard.bin");

    let db5_content = format!(
        "\"{}\",\"{}\",\"DE\",\"Germany\",\"Berlin\",\"Berlin\",\"52.5200\",\"13.4050\",\"10115\",\"+01:00\"\n",
        ip_to_u32("5.0.0.0"),
        ip_to_u32("5.255.255.255")
    );
    let mut f = File::create(&db5_path).unwrap();
    f.write_all(db5_content.as_bytes()).unwrap();

    let opt = OptimizationConfig {
        compact_ranges: false,
        family: RecordFamily::Standard,
        layout: StorageLayout::Soa,
        ..Default::default()
    };

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db5_path))
        .optimization(opt);

    let stats = compile(opts).unwrap();
    assert!(!stats.is_compact);
    assert!(stats.is_soa);

    let reader = IpAtlasReader::open(&out_bin).unwrap();
    assert!(reader.is_soa());
    assert!(!reader.is_compact());
    assert_eq!(reader.layout(), StorageLayout::Soa);
    assert_eq!(reader.family(), RecordFamily::Standard);
    assert_eq!(reader.version(), 0x0502);

    let rec = reader
        .lookup_str("5.10.20.30")
        .expect("DE record not found");
    assert_eq!(rec.country, "DE");
    assert_eq!(rec.city, "Berlin");
    assert_eq!(
        reader.lookup_country_code_u32(ip_to_u32("5.10.20.30")),
        Some("DE")
    );
}
