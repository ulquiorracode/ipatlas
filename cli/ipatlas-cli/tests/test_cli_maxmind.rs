use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_maxmind_compilation_and_lookup() {
    let dir = tempdir().unwrap();
    let blocks_csv = dir.path().join("blocks.csv");
    let locations_csv = dir.path().join("locations.csv");
    let out_bin = dir.path().join("maxmind_test.bin");

    // Sample Locations CSV (MaxMind GeoLite2 format)
    let locations_content = "\
geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,subdivision_1_iso_code,subdivision_1_name,subdivision_2_iso_code,subdivision_2_name,city_name,metro_code,time_zone,is_in_european_union\n\
5368361,en,NA,\"North America\",US,\"United States\",CA,California,,,Los Angeles,803,America/Los_Angeles,0\n";
    std::fs::write(&locations_csv, locations_content).unwrap();

    // Sample Blocks CSV (MaxMind GeoLite2 City format)
    let blocks_content = "\
network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,postal_code,latitude,longitude,accuracy_radius\n\
8.8.8.0/24,5368361,5368361,,0,0,90001,34.05,-118.25,50\n";
    std::fs::write(&blocks_csv, blocks_content).unwrap();

    // Run ipatlas compile --maxmind-blocks ... --maxmind-locations ... -o ...
    let bin_path = env!("CARGO_BIN_EXE_ipatlas");
    let compile_status = Command::new(bin_path)
        .arg("compile")
        .arg("--maxmind-blocks")
        .arg(&blocks_csv)
        .arg("--maxmind-locations")
        .arg(&locations_csv)
        .arg("-o")
        .arg(&out_bin)
        .status()
        .expect("Failed to execute ipatlas CLI");

    assert!(compile_status.success(), "CLI compile must succeed");
    assert!(out_bin.exists(), "Output binary must exist");

    // Run ipatlas lookup 8.8.8.8 ...
    let output = Command::new(bin_path)
        .arg("lookup")
        .arg(&out_bin)
        .arg("8.8.8.8")
        .output()
        .expect("Failed to execute ipatlas lookup");

    assert!(output.status.success(), "CLI lookup must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("US"),
        "Lookup output must contain country US"
    );
    assert!(
        stdout.contains("Los Angeles"),
        "Lookup output must contain city Los Angeles"
    );
}
