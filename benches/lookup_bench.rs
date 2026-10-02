use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use tempfile::tempdir;

use ipatlas::{compile, CompilerOptions, IpAtlasReader};

fn setup_benchmark_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("bench_db.csv");
    let px_path = dir.path().join("bench_px.csv");
    let out_bin = dir.path().join("bench.bin");

    let mut db_file = File::create(&db_path).unwrap();
    let mut px_file = File::create(&px_path).unwrap();

    let mut curr: u32 = 16_777_216; // 1.0.0.0
    for i in 0..10_000 {
        let step = 256;
        let ip_from = curr;
        let ip_to = curr + step - 1;
        curr = ip_to + 1;

        writeln!(
            db_file,
            "{},{},US,United States,CA,Los Angeles,34.05,-118.24",
            ip_from, ip_to
        )
        .unwrap();

        if i % 4 == 0 {
            writeln!(
                px_file,
                "{},{},VPN,US,United States,CA,Los Angeles,Cloud Provider,host.com,DCH,13335,AS_NAME,2026-01-01,VPN",
                ip_from, ip_to
            )
            .unwrap();
        }
    }

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db_path))
        .proxy(Some(&px_path))
        .compression(false, false);

    compile(opts).unwrap();
    (dir, out_bin)
}

fn bench_lookups(c: &mut Criterion) {
    let (_dir, bin_path) = setup_benchmark_db();
    let reader = IpAtlasReader::open(&bin_path).unwrap();

    let target_ip: Ipv4Addr = "1.0.1.50".parse().unwrap();
    let target_u32 = u32::from(target_ip);

    let mut group = c.benchmark_group("lookup");

    group.bench_function("lookup_u32 (zero-copy ref)", |b| {
        b.iter(|| {
            let res = reader.lookup_u32(black_box(target_u32));
            black_box(res)
        });
    });

    group.bench_function("lookup_ref (ip into)", |b| {
        b.iter(|| {
            let res = reader.lookup_ref(black_box(target_ip));
            black_box(res)
        });
    });

    group.bench_function("lookup (owned strings)", |b| {
        b.iter(|| {
            let res = reader.lookup(black_box(target_ip));
            black_box(res)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_lookups);
criterion_main!(benches);
