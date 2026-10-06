use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use tempfile::tempdir;

use ipatlas_core::{
    compile, CompilerOptions, IpAtlasPipelineExt, IpAtlasReader, LookupContext, LookupError,
    LookupIntent,
};

fn ip_to_u32(s: &str) -> u32 {
    let ip: Ipv4Addr = s.parse().unwrap();
    u32::from(ip)
}

fn create_test_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let db5_path = dir.path().join("test_db5.csv");
    let px10_path = dir.path().join("test_px10.csv");
    let out_bin = dir.path().join("unified.bin");

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

    compile(opts).expect("compile test db");
    (dir, out_bin)
}

#[test]
fn test_stitch_pipeline_bogon_short_circuit() {
    let (_dir, out_bin) = create_test_db();
    let reader = IpAtlasReader::open(&out_bin).expect("open reader");

    let mut ctx = LookupContext::new();

    // 1. Local loopback IPv4
    let res_loopback = reader
        .query_pipeline(&mut ctx, LookupIntent::new("127.0.0.1".parse().unwrap()))
        .expect("bogon lookup");
    assert!(res_loopback.is_bogon);
    assert_eq!(res_loopback.record.as_ref().unwrap().country, "-");
    assert_eq!(ctx.bogon_short_circuits, 1);

    // 2. Private LAN IPv4 (192.168.1.1)
    let res_lan = reader
        .query_pipeline(&mut ctx, LookupIntent::new("192.168.1.1".parse().unwrap()))
        .expect("bogon lookup");
    assert!(res_lan.is_bogon);
    assert_eq!(ctx.bogon_short_circuits, 2);

    // 3. IPv6 Loopback (::1)
    let res_v6 = reader
        .query_pipeline(&mut ctx, LookupIntent::new("::1".parse().unwrap()))
        .expect("bogon v6");
    assert!(res_v6.is_bogon);
    assert_eq!(ctx.bogon_short_circuits, 3);
}

#[test]
fn test_stitch_pipeline_public_resolution_and_telemetry() {
    let (_dir, out_bin) = create_test_db();
    let reader = IpAtlasReader::open(&out_bin).expect("open reader");

    let mut ctx = LookupContext::new();

    // Normal clean IP: 1.0.5.10 (US)
    let ip: IpAddr = "1.0.5.10".parse().unwrap();
    let res = reader
        .query_pipeline(&mut ctx, LookupIntent::new(ip))
        .expect("query pipeline");

    assert!(!res.is_bogon);
    assert!(!res.is_threat);
    let record = res.record.expect("record found");
    assert_eq!(record.country, "US");
    assert_eq!(record.city, "Los Angeles");

    assert_eq!(ctx.dispatches, 1);
    assert_eq!(ctx.successful_lookups, 1);
    assert!(ctx.total_latency_nanos > 0);
    assert!(ctx.avg_latency_nanos() > 0.0);
}

#[test]
fn test_stitch_pipeline_threat_policy_enforcement() {
    let (_dir, out_bin) = create_test_db();
    let reader = IpAtlasReader::open(&out_bin).expect("open reader");

    let mut ctx = LookupContext::new();
    let botnet_ip: IpAddr = "1.0.20.100".parse().unwrap();

    // 1. Permissive query allows threat observation
    let permissive = reader
        .query_pipeline(&mut ctx, LookupIntent::new(botnet_ip))
        .expect("permissive allows threat");
    assert!(permissive.is_threat);
    assert!(permissive.flags.is_proxy());
    assert!(permissive.flags.is_botnet());

    // 2. Strict query halts execution at terminal / policy
    let strict_res = reader.query_pipeline(&mut ctx, LookupIntent::strict(botnet_ip));
    assert!(matches!(strict_res, Err(LookupError::ThreatRejected(_))));
}
