use std::net::IpAddr;

use ipatlas_adapter_maxminddb_compat::{geoip2, Reader};
use ipatlas_core::{compile, CompilerOptions};
use tempfile::tempdir;

#[test]
fn test_maxminddb_compat_lookup() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("geo.csv");
    let out_bin = dir.path().join("compat_test.bin");

    let ip_u32 = 0x08080808u32;
    std::fs::write(
        &db_path,
        format!("{ip_u32},{ip_u32},US,United States,CA,Mountain View,37.42,-122.08\n"),
    )
    .unwrap();

    let opts = CompilerOptions::new(&out_bin).geo(Some(&db_path));
    compile(opts).unwrap();

    // 1. Open using maxminddb syntax
    let reader = Reader::open_readfile(&out_bin).unwrap();

    // 2. Lookup CityRecord using maxminddb syntax
    let ip: IpAddr = "8.8.8.8".parse().unwrap();
    let city_record: geoip2::CityRecord = reader.lookup(ip).unwrap();

    let country = city_record.country.unwrap();
    assert_eq!(country.iso_code.as_deref(), Some("US"));
    assert_eq!(
        country.names.unwrap().get("en").map(|s| s.as_str()),
        Some("US")
    );

    let city = city_record.city.unwrap();
    assert_eq!(
        city.names.unwrap().get("en").map(|s| s.as_str()),
        Some("Mountain View")
    );

    let loc = city_record.location.unwrap();
    assert!((loc.latitude.unwrap() - 37.42).abs() < 0.01);

    // 3. Lookup CountryRecord using maxminddb syntax
    let country_record: geoip2::CountryRecord = reader.lookup(ip).unwrap();
    assert_eq!(
        country_record.country.unwrap().iso_code.as_deref(),
        Some("US")
    );

    // 4. Missing IP
    let missing_ip: IpAddr = "1.2.3.4".parse().unwrap();
    let err = reader.lookup::<geoip2::CityRecord>(missing_ip);
    assert!(err.is_err());
}
