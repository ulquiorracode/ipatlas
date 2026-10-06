use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use tempfile::tempdir;

use ipatlas_core::{compile, CompilerOptions, HotReloadDatabase};

fn ip(s: &str) -> u32 {
    let addr: Ipv4Addr = s.parse().unwrap();
    u32::from(addr)
}

#[test]
fn test_hot_reload_atomic_swap() {
    let dir = tempdir().unwrap();
    let db1_csv = dir.path().join("db1.csv");
    let db2_csv = dir.path().join("db2.csv");
    let live_bin = dir.path().join("live.bin");

    // Version 1: 1.0.0.0/24 is US
    let mut f1 = File::create(&db1_csv).unwrap();
    writeln!(
        f1,
        "{},{},US,United States,CA,Los Angeles,34.05,-118.24",
        ip("1.0.0.0"),
        ip("1.0.0.255")
    )
    .unwrap();
    drop(f1);

    compile(CompilerOptions::new(&live_bin).geo(Some(&db1_csv))).expect("compile db1");

    let hot_db = HotReloadDatabase::open(&live_bin).expect("open initial db");

    // Verify initial state
    {
        let reader = hot_db.load();
        let target: std::net::IpAddr = "1.0.0.10".parse().unwrap();
        let rec = reader.lookup_ref(target).expect("lookup db1");
        assert_eq!(rec.country, "US");
        assert_eq!(rec.city, "Los Angeles");
    }

    // Version 2: Update file on disk so 1.0.0.0/24 is JP (Tokyo)
    let mut f2 = File::create(&db2_csv).unwrap();
    writeln!(
        f2,
        "{},{},JP,Japan,Tokyo,Tokyo,35.68,139.69",
        ip("1.0.0.0"),
        ip("1.0.0.255")
    )
    .unwrap();
    drop(f2);

    compile(CompilerOptions::new(&live_bin).geo(Some(&db2_csv))).expect("compile db2 over live");

    // Hot reload
    hot_db.reload().expect("hot reload new file");

    // Verify atomic transition
    {
        let reader = hot_db.load();
        let target: std::net::IpAddr = "1.0.0.10".parse().unwrap();
        let rec = reader.lookup_ref(target).expect("lookup db2");
        assert_eq!(rec.country, "JP");
        assert_eq!(rec.city, "Tokyo");
    }
}
