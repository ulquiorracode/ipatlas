use ipatlas_adapter_maxmind::MaxMindCityAdapter;
use ipatlas_core::DatasetIngestionAdapter;
use tempfile::tempdir;

#[test]
fn test_maxmind_adapter_ingestion_and_resolution() {
    let dir = tempdir().unwrap();
    let blocks_csv = dir.path().join("blocks.csv");
    let locations_csv = dir.path().join("locations.csv");

    // Sample Locations CSV (MaxMind GeoLite2 format)
    let locations_content = "\
geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,subdivision_1_iso_code,subdivision_1_name,subdivision_2_iso_code,subdivision_2_name,city_name,metro_code,time_zone,is_in_european_union\n\
5368361,en,NA,\"North America\",US,\"United States\",CA,California,,,Los Angeles,803,America/Los_Angeles,0\n\
2988507,en,EU,Europe,FR,France,IDF,\"Ile-de-France\",,,Paris,,Europe/Paris,1\n";
    std::fs::write(&locations_csv, locations_content).unwrap();

    // Sample Blocks CSV (MaxMind GeoLite2 City format)
    let blocks_content = "\
network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,postal_code,latitude,longitude,accuracy_radius\n\
1.2.3.0/24,5368361,5368361,,0,0,90001,34.05,-118.25,50\n\
81.2.69.144/28,2988507,2988507,,0,0,,48.85,2.35,10\n";
    std::fs::write(&blocks_csv, blocks_content).unwrap();

    let mut adapter = MaxMindCityAdapter::open(&blocks_csv, &locations_csv).unwrap();
    let records: Vec<_> = adapter.parse_v4().collect();

    assert_eq!(records.len(), 2);

    // Record 1: 1.2.3.0/24 -> 1.2.3.0 to 1.2.3.255
    let r1 = &records[0];
    assert_eq!(r1.ip_from, u32::from(std::net::Ipv4Addr::new(1, 2, 3, 0)));
    assert_eq!(r1.ip_to, u32::from(std::net::Ipv4Addr::new(1, 2, 3, 255)));
    assert_eq!(&r1.country, b"US");
    assert_eq!(r1.region.as_deref(), Some("California"));
    assert_eq!(r1.city.as_deref(), Some("Los Angeles"));

    // Record 2: 81.2.69.144/28 -> FR Paris
    let r2 = &records[1];
    assert_eq!(&r2.country, b"FR");
    assert_eq!(r2.city.as_deref(), Some("Paris"));
}

#[test]
fn test_maxmind_adapter_missing_file_returns_err() {
    let dir = tempdir().unwrap();
    let missing_blocks = dir.path().join("non_existent_blocks.csv");
    let locations_csv = dir.path().join("locations.csv");
    std::fs::write(&locations_csv, "geoname_id,...\n").unwrap();

    let res = MaxMindCityAdapter::open(&missing_blocks, &locations_csv);
    assert!(
        res.is_err(),
        "Opening non-existent blocks file must fail with io::Error"
    );
}
