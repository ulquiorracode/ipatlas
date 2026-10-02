use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use tempfile::tempdir;

use ipatlas::{
    compile, quantize_coordinate, CompilerOptions, IpAtlasReader, OptimizationConfig, Preset,
    RECORD_SIZE_V4_COMPACT,
};

fn ip_to_u32(s: &str) -> u32 {
    let ip: Ipv4Addr = s.parse().unwrap();
    u32::from(ip)
}

#[test]
fn test_presets_firewall_and_country_coalescing() {
    let dir = tempdir().unwrap();
    let db5_path = dir.path().join("test_db5.csv");
    let px10_path = dir.path().join("test_px10.csv");

    let db5_content = format!(
        "{},{},US,United States,California,Los Angeles,34.05,-118.24\n\
         {},{},JP,Japan,Tokyo,Tokyo,35.68,139.69\n\
         {},{},RU,Russian Federation,Moskva,Moscow,55.75,37.61\n",
        ip_to_u32("1.0.0.0"),
        ip_to_u32("1.0.15.255"),
        ip_to_u32("1.0.16.0"),
        ip_to_u32("1.0.31.255"),
        ip_to_u32("1.0.32.0"),
        ip_to_u32("1.0.47.255")
    );
    let mut f = File::create(&db5_path).unwrap();
    f.write_all(db5_content.as_bytes()).unwrap();

    let px10_content = format!(
        "{},{},PUB,JP,Japan,Tokyo,Tokyo,DataCenter Host,dc.jp,DCH,13335,CLOUDFLARE,2026-09-01,BOTNET\n",
        ip_to_u32("1.0.20.0"),
        ip_to_u32("1.0.20.255")
    );
    let mut f2 = File::create(&px10_path).unwrap();
    f2.write_all(px10_content.as_bytes()).unwrap();

    // 1. Country-Only preset: JP range with internal proxy should coalesce into a single JP interval!
    let country_bin = dir.path().join("country.bin");
    let opts_c = CompilerOptions::new(&country_bin)
        .preset(Preset::Country)
        .geo(Some(&db5_path))
        .proxy(Some(&px10_path));

    let stats_c = compile(opts_c).unwrap();
    assert_eq!(stats_c.records, 3);
    assert_eq!(stats_c.profiles, 3);
    assert_eq!(stats_c.cities, 1);

    let reader_c = IpAtlasReader::open(&country_bin).unwrap();
    let rec_c = reader_c
        .lookup_str("1.0.20.55")
        .expect("JP record not found");
    assert_eq!(rec_c.country, "JP");
    assert_eq!(rec_c.city, "");
    assert!(!rec_c.flags.is_proxy());

    // 2. Firewall preset: Country + ASN + Threats
    let fw_bin = dir.path().join("firewall.bin");
    let opts_fw = CompilerOptions::new(&fw_bin)
        .preset(Preset::Firewall)
        .geo(Some(&db5_path))
        .proxy(Some(&px10_path));

    let stats_fw = compile(opts_fw).unwrap();
    assert_eq!(stats_fw.cities, 1);
    let reader_fw = IpAtlasReader::open(&fw_bin).unwrap();
    let rec_fw = reader_fw
        .lookup_str("1.0.20.55")
        .expect("Firewall record not found");
    assert_eq!(rec_fw.country, "JP");
    assert!(rec_fw.flags.is_proxy());
    assert!(rec_fw.flags.is_botnet());
    assert_eq!(rec_fw.asn, 13335);
    assert_eq!(rec_fw.city, "");
}

#[test]
fn test_compact_v4_1_layout() {
    let dir = tempdir().unwrap();
    let db5_path = dir.path().join("compact_db5.csv");
    let out_bin = dir.path().join("compact.bin");

    let db5_content = format!(
        "{},{},US,United States,California,Los Angeles,34.05,-118.24\n\
         {},{},JP,Japan,Tokyo,Tokyo,35.68,139.69\n",
        ip_to_u32("1.0.0.0"),
        ip_to_u32("1.0.15.255"),
        ip_to_u32("1.0.16.0"),
        ip_to_u32("1.0.31.255")
    );
    let mut f = File::create(&db5_path).unwrap();
    f.write_all(db5_content.as_bytes()).unwrap();

    let opt = OptimizationConfig {
        compact_ranges: true,
        ..Default::default()
    };

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db5_path))
        .optimization(opt);

    let stats = compile(opts).unwrap();
    assert!(stats.is_compact);

    let reader = IpAtlasReader::open(&out_bin).unwrap();
    assert!(reader.is_compact());
    assert_eq!(reader.version(), 0x0401);
    assert_eq!(reader.len(), 2);
    assert_eq!(reader.ranges_compact().len(), 2);
    assert_eq!(
        std::mem::size_of_val(&reader.ranges_compact()[0]),
        RECORD_SIZE_V4_COMPACT as usize
    );

    // Verify lookup works seamlessly on compact layout
    let rec = reader.lookup_str("1.0.5.10").expect("US record not found");
    assert_eq!(rec.country, "US");
    assert_eq!(rec.city, "Los Angeles");

    let rec_jp = reader.lookup_str("1.0.20.1").expect("JP record not found");
    assert_eq!(rec_jp.country, "JP");
}

#[test]
fn test_optimization_flags_levels_and_symmetric_quantization() {
    let mut opt = OptimizationConfig::default();
    assert!(opt.coalesce);
    assert!(opt.dedup_profiles);

    opt.parse_arg("-O0").unwrap();
    assert!(!opt.coalesce);

    opt.parse_arg("-O2").unwrap();
    assert!(opt.coalesce);
    assert!(opt.normalize_strings);
    assert!(!opt.lossy_coords);

    opt.parse_arg("-O3").unwrap();
    assert!(opt.coalesce);
    assert!(opt.normalize_strings);
    assert!(opt.lossy_coords);

    opt.parse_arg("lossy-coords,prune-empty,compact").unwrap();
    assert!(opt.lossy_coords);
    assert!(opt.prune_empty);
    assert!(opt.compact_ranges);

    // Test symmetric quantization without zero-truncation bias
    assert_eq!(quantize_coordinate(3405), 3410);
    assert_eq!(quantize_coordinate(-3405), -3410);
    assert_eq!(quantize_coordinate(3402), 3400);
    assert_eq!(quantize_coordinate(-3402), -3400);
}
