use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use tempfile::tempdir;

use ipatlas::{compile, CompilerOptions, IpAtlasReader};

fn ip_to_u32(s: &str) -> u32 {
    let ip: Ipv4Addr = s.parse().unwrap();
    u32::from(ip)
}

#[test]
fn test_compile_and_lookup_full() {
    let dir = tempdir().unwrap();
    let db5_path = dir.path().join("test_db5.csv");
    let px10_path = dir.path().join("test_px10.csv");
    let out_bin = dir.path().join("unified.bin");

    // DB5: ip_from, ip_to, cc, country_name, region, city, lat, lon
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

    // PX10: ip_from, ip_to, proxy_type, cc, country_name, region, city, isp, domain, usage_type, asn, as_name, last_seen, threat
    let px10_content = format!(
        "{},{},PUB,JP,Japan,Tokyo,Tokyo,DataCenter Host,dc.jp,DCH,13335,CLOUDFLARE,2026-09-01,BOTNET\n",
        ip_to_u32("1.0.20.0"),
        ip_to_u32("1.0.20.255")
    );
    let mut f2 = File::create(&px10_path).unwrap();
    f2.write_all(px10_content.as_bytes()).unwrap();

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db5_path))
        .proxy(Some(&px10_path));

    let stats = compile(opts).unwrap();
    assert_eq!(stats.records, 5);
    assert_eq!(stats.profiles, 4);
    assert!(out_bin.exists());

    let reader = IpAtlasReader::open(&out_bin).unwrap();
    assert_eq!(reader.len(), 5);

    // 1. Clean residential US
    let res_us = reader.lookup_str("1.0.5.10").expect("US record not found");
    assert_eq!(res_us.country, "US");
    assert_eq!(res_us.city, "Los Angeles");
    assert_eq!(res_us.region, "California");
    assert!((res_us.latitude - 34.05).abs() < 0.01);
    assert!(!res_us.flags.is_proxy());
    assert!(!res_us.flags.is_datacenter());

    // 2. Clean Tokyo
    let res_jp = reader.lookup_str("1.0.18.1").expect("JP record not found");
    assert_eq!(res_jp.country, "JP");
    assert_eq!(res_jp.city, "Tokyo");
    assert!(!res_jp.flags.is_proxy());

    // 3. Proxy in Tokyo (DCH + BOTNET + ASN 13335)
    let res_proxy = reader
        .lookup_str("1.0.20.55")
        .expect("Proxy record not found");
    assert_eq!(res_proxy.country, "JP");
    assert_eq!(res_proxy.city, "Tokyo");
    assert_eq!(res_proxy.isp, "DataCenter Host");
    assert_eq!(res_proxy.asn, 13335);
    assert!(res_proxy.flags.is_proxy());
    assert!(res_proxy.flags.is_datacenter());
    assert!(res_proxy.flags.is_botnet());

    // 4. Clean Moscow
    let res_ru = reader.lookup_str("1.0.40.1").expect("RU record not found");
    assert_eq!(res_ru.country, "RU");
    assert_eq!(res_ru.city, "Moscow");
    assert!(!res_ru.flags.is_proxy());

    // 5. IP outside ranges
    assert!(reader.lookup_str("8.8.8.8").is_none());
}

#[test]
fn test_compile_db1_px1_heterogeneous() {
    let dir = tempdir().unwrap();
    let db1_path = dir.path().join("test_db1.csv");
    let px1_path = dir.path().join("test_px1.csv");
    let out_bin = dir.path().join("minimal.bin");

    // DB1: 4 columns
    let db1_content = format!(
        "{},{},DE,Germany\n",
        ip_to_u32("2.0.0.0"),
        ip_to_u32("2.0.255.255")
    );
    let mut f = File::create(&db1_path).unwrap();
    f.write_all(db1_content.as_bytes()).unwrap();

    // PX1: 5 columns
    let px1_content = format!(
        "{},{},VPN,DE,Germany\n",
        ip_to_u32("2.0.50.0"),
        ip_to_u32("2.0.50.255")
    );
    let mut f2 = File::create(&px1_path).unwrap();
    f2.write_all(px1_content.as_bytes()).unwrap();

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db1_path))
        .proxy(Some(&px1_path));

    let stats = compile(opts).unwrap();
    assert_eq!(stats.records, 3);

    let reader = IpAtlasReader::open(&out_bin).unwrap();
    let rec = reader.lookup_str("2.0.50.1").expect("DE proxy not found");
    assert_eq!(rec.country, "DE");
    assert!(rec.flags.is_proxy());
    assert_eq!(rec.city, "");
}
