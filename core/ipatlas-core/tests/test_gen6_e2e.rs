use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use ipatlas_core::models::{OptimizationConfig, StorageLayout};
use ipatlas_core::{compile, CompilerOptions, IpAtlasReader};

#[test]
fn test_gen6_columnar_stitch_e2e_compilation_and_lookup() {
    let dir = tempdir().unwrap();
    let db5_path = dir.path().join("test_db5.csv");
    let px10_path = dir.path().join("test_px10.csv");
    let out_bin = dir.path().join("gen6_unified.bin");

    // Generate 2,000 synthetic Geo and Proxy intervals across multiple /16 blocks
    let mut db5_file = File::create(&db5_path).unwrap();
    let mut px10_file = File::create(&px10_path).unwrap();

    let mut curr: u32 = 16_777_216; // 1.0.0.0
    for i in 0..2_000 {
        let step = 256;
        let ip_from = curr;
        let ip_to = curr + step - 1;
        curr = ip_to + 1;

        let country = if i % 2 == 0 { "US" } else { "DE" };
        let city = if i % 3 == 0 {
            "New York"
        } else if i % 3 == 1 {
            "Berlin"
        } else {
            "Tokyo"
        };
        let region = if i % 2 == 0 { "California" } else { "Berlin" };
        let lat = 34.05 + (i as f64 * 0.001);
        let lon = -118.24 + (i as f64 * 0.001);

        writeln!(
            db5_file,
            "{},{},{},Country,{},{},{:.2},{:.2}",
            ip_from, ip_to, country, region, city, lat, lon
        )
        .unwrap();

        if i % 4 == 0 {
            writeln!(
                px10_file,
                "{},{},PUB,{},Country,{},{},Cloudflare Host,dc.com,DCH,13335,CLOUDFLARE,2026-11-01,BOTNET",
                ip_from, ip_to, country, region, city
            )
            .unwrap();
        }
    }
    db5_file.flush().unwrap();
    px10_file.flush().unwrap();

    let opt = OptimizationConfig {
        layout: StorageLayout::Columnar,
        ..Default::default()
    };

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db5_path))
        .proxy(Some(&px10_path))
        .optimization(opt);

    let stats = compile(opts).unwrap();
    assert_eq!(stats.records, 2_000);
    assert!(out_bin.exists());

    // Open via zero-copy reader
    let reader = IpAtlasReader::open(&out_bin).unwrap();
    assert_eq!(reader.len_v4(), 2_000);
    assert_eq!(reader.layout(), StorageLayout::Columnar);

    // Query 1: IP in range 0 (1.0.0.10)
    let res0 = reader.lookup_u32(16_777_216 + 10).unwrap();
    assert_eq!(res0.country, "US");
    assert_eq!(res0.city, "New York");
    assert_eq!(res0.isp, "Cloudflare Host");
    assert!(res0.flags.is_proxy());
    assert!(res0.flags.is_datacenter());

    // Query 2: IP in range 1250 (across chunk boundaries, non-proxy range)
    let target_ip_1250 = 16_777_216 + 1250 * 256 + 42;
    let res1250 = reader.lookup_u32(target_ip_1250).unwrap();
    assert_eq!(res1250.country, "US"); // 1250 % 2 == 0 -> US
    assert_eq!(res1250.city, "Tokyo"); // 1250 % 3 == 2 -> Tokyo
    assert!(!res1250.flags.is_proxy());

    // Query 3: Non-existent IP (outside compiled intervals)
    let res_miss = reader.lookup_u32(0xFA00_0001);
    assert!(res_miss.is_none());
}
