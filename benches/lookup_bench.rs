use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use tempfile::tempdir;

use ipatlas::{compile, CompilerOptions, IpAtlasReader, OptimizationConfig};

fn setup_benchmark_db(compact: bool) -> (tempfile::TempDir, std::path::PathBuf) {
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

    let opt = OptimizationConfig {
        compact_ranges: compact,
        ..Default::default()
    };

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db_path))
        .proxy(Some(&px_path))
        .optimization(opt);

    compile(opts).unwrap();
    (dir, out_bin)
}

fn bench_lookups(c: &mut Criterion) {
    let (_dir, bin_path) = setup_benchmark_db(false);
    let reader = IpAtlasReader::open(&bin_path).unwrap();

    let (_dir_c, bin_path_c) = setup_benchmark_db(true);
    let reader_compact = IpAtlasReader::open(&bin_path_c).unwrap();

    let target_ip: Ipv4Addr = "1.0.1.50".parse().unwrap();
    let target_u32 = u32::from(target_ip);

    // Generate 1024 realistic random pseudo-random IPs (hits & misses) to defeat L1 cache & branch predictor
    let mut ip_seed: u32 = 0x12345678;
    let mut random_ips = Vec::with_capacity(1024);
    for _ in 0..1024 {
        ip_seed = ip_seed.wrapping_mul(1664525).wrapping_add(1013904223);
        random_ips.push(ip_seed);
    }

    let mut group = c.benchmark_group("lookup");

    // 1. Hot in-cache single IP lookup
    group.bench_function("hot_l1_lookup_u32", |b| {
        b.iter(|| {
            let res = reader.lookup_u32(black_box(target_u32));
            black_box(res)
        });
    });

    // 2. Realistic random lookup (DRAM/L2/L3 cache misses)
    let mut idx = 0;
    group.bench_function("random_cache_miss_lookup_u32", |b| {
        b.iter(|| {
            let ip = random_ips[idx % random_ips.len()];
            idx = idx.wrapping_add(1);
            let res = reader.lookup_u32(black_box(ip));
            black_box(res)
        });
    });

    // 3. V4.1 Compact layout (8 bytes per range)
    group.bench_function("compact_v4_1_lookup_u32", |b| {
        b.iter(|| {
            let res = reader_compact.lookup_u32(black_box(target_u32));
            black_box(res)
        });
    });

    // 3b. Flags-only fast path (No string resolution, no memchr scans)
    group.bench_function("flags_only_lookup_u32", |b| {
        b.iter(|| {
            let res = reader_compact.lookup_flags_u32(black_box(target_u32));
            black_box(res)
        });
    });

    // 3c. Direct threat predicate check (is_threat)
    group.bench_function("is_threat_predicate_u32", |b| {
        b.iter(|| {
            let res = reader_compact.is_threat_u32(black_box(target_u32));
            black_box(res)
        });
    });

    // 4. Owned strings conversion
    group.bench_function("owned_strings_lookup", |b| {
        b.iter(|| {
            let res = reader.lookup(black_box(target_ip));
            black_box(res)
        });
    });

    // 5. Experimental V5-Succinct Elias-Fano Bitvector lookup
    let succinct_table = {
        use ipatlas::compiler::succinct::SuccinctIntervalTable;
        use ipatlas::models::{ProfileV4, RangeV4};
        let ranges: Vec<RangeV4> = reader
            .ranges()
            .iter()
            .map(|r| RangeV4::new(r.ip_from, r.ip_to, r.profile_id))
            .collect();
        let profiles: Vec<ProfileV4> = reader.profiles().to_vec();
        SuccinctIntervalTable::build(&ranges, profiles)
    };

    group.bench_function("succinct_elias_fano_lookup", |b| {
        b.iter(|| {
            let res = succinct_table.lookup(black_box(target_u32));
            black_box(res)
        });
    });

    // 6. AoS vs SoA Comparative Architecture Benchmark
    let (_dir_soa, bin_path_soa) = {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("bench_db.csv");
        let px_path = dir.path().join("bench_px.csv");
        let out_bin = dir.path().join("bench_soa.bin");

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

        let opt = OptimizationConfig {
            compact_ranges: true,
            family: ipatlas::RecordFamily::Compact,
            layout: ipatlas::StorageLayout::Soa,
            ..Default::default()
        };

        let opts = CompilerOptions::new(&out_bin)
            .geo(Some(&db_path))
            .proxy(Some(&px_path))
            .optimization(opt);

        compile(opts).unwrap();
        (dir, out_bin)
    };
    let reader_soa = IpAtlasReader::open(&bin_path_soa).unwrap();

    group.bench_function("soa_compact_lookup_u32", |b| {
        b.iter(|| {
            let res = reader_soa.lookup_u32(black_box(target_u32));
            black_box(res)
        });
    });

    group.bench_function("soa_compact_flags_u32", |b| {
        b.iter(|| {
            let res = reader_soa.lookup_flags_u32(black_box(target_u32));
            black_box(res)
        });
    });

    // 7. Chunk Size Evaluation for Blocked-Zstd Decompression
    // Compare 4KB (page), 16KB, 64KB (aligned struct boundary: 8192 * 8B), and 256KB
    let raw_records = reader_compact.ranges_compact();
    let encode_chunk = |count: usize| -> Vec<u8> {
        let bytes = zerocopy::IntoBytes::as_bytes(&raw_records[..count.min(raw_records.len())]);
        zstd::encode_all(bytes, 3).unwrap()
    };

    let chunk_4k_data = encode_chunk(512); // 512 * 8B = 4,096 bytes (4 KB)
    let chunk_16k_data = encode_chunk(2048); // 2048 * 8B = 16,384 bytes (16 KB)
    let chunk_64k_data = encode_chunk(8192); // 8192 * 8B = 65,536 bytes (64 KB)
    let chunk_256k_data = encode_chunk(32768.min(raw_records.len())); // ~256 KB

    group.bench_function("chunk_decompress_4kb", |b| {
        b.iter(|| {
            let decompressed = zstd::decode_all(&chunk_4k_data[..]).unwrap();
            black_box(decompressed.len())
        });
    });

    group.bench_function("chunk_decompress_16kb", |b| {
        b.iter(|| {
            let decompressed = zstd::decode_all(&chunk_16k_data[..]).unwrap();
            black_box(decompressed.len())
        });
    });

    group.bench_function("chunk_decompress_64kb", |b| {
        b.iter(|| {
            let decompressed = zstd::decode_all(&chunk_64k_data[..]).unwrap();
            black_box(decompressed.len())
        });
    });

    group.bench_function("chunk_decompress_256kb", |b| {
        b.iter(|| {
            let decompressed = zstd::decode_all(&chunk_256k_data[..]).unwrap();
            black_box(decompressed.len())
        });
    });

    group.finish();
}

criterion_group!(benches, bench_lookups);
criterion_main!(benches);
