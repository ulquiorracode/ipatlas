use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use tempfile::tempdir;

use ipatlas_core::{compile, CompilerOptions, IpAtlasReader, OptimizationConfig};

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

    // 1. Generate 1024 realistic random IPs sampled from valid intervals (true hits)
    // to measure production non-cached hit latency including profile & string decoding.
    let mut ip_seed: u32 = 0x12345678;
    let mut random_hit_ips = Vec::with_capacity(1024);
    for _ in 0..1024 {
        ip_seed = ip_seed.wrapping_mul(1664525).wrapping_add(1013904223);
        // Map seed into valid database interval space: [16_777_216 .. 16_777_216 + 10_000 * 256)
        let offset = (ip_seed as usize) % (10_000 * 256);
        random_hit_ips.push(16_777_216 + offset as u32);
    }

    // 2. Generate 1024 arbitrary random IPs across full u32 space (mostly misses)
    let mut random_miss_ips = Vec::with_capacity(1024);
    for _ in 0..1024 {
        ip_seed = ip_seed.wrapping_mul(1664525).wrapping_add(1013904223);
        // Force high range > 200.0.0.0 outside test DB to test pure miss path
        random_miss_ips.push(3_355_443_200 + (ip_seed % 10_000_000));
    }

    let mut group = c.benchmark_group("lookup");

    // 1. Hot in-cache single IP lookup
    group.bench_function("hot_l1_lookup_u32", |b| {
        b.iter(|| {
            let res = reader.lookup_u32(black_box(target_u32));
            black_box(res)
        });
    });

    // 2a. Realistic random hit lookup (cache-miss binary search + profile resolution)
    let mut hit_idx = 0;
    group.bench_function("random_hit_lookup_u32", |b| {
        b.iter(|| {
            let ip = random_hit_ips[hit_idx % random_hit_ips.len()];
            hit_idx = hit_idx.wrapping_add(1);
            let res = reader.lookup_u32(black_box(ip));
            black_box(res)
        });
    });

    // 2b. Realistic random miss lookup (pure binary search key probe returning None)
    let mut miss_idx = 0;
    group.bench_function("random_cache_miss_lookup_u32", |b| {
        b.iter(|| {
            let ip = random_miss_ips[miss_idx % random_miss_ips.len()];
            miss_idx = miss_idx.wrapping_add(1);
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

    // 3b_batch. Batch lookup 64 IPs (Amortized throughput per IP)
    let batch_ips: Vec<u32> = (0..64).map(|i| target_u32.wrapping_add(i * 256)).collect();
    let mut batch_flags = vec![None; 64];
    group.bench_function("batch_64_flags_lookup_u32", |b| {
        b.iter(|| {
            reader_compact.lookup_flags_batch_u32(black_box(&batch_ips), black_box(&mut batch_flags));
            black_box(&batch_flags[0]);
        });
    });

    // 3c. Profile-only fast path (Returns raw 20B ProfileGen4 without string resolution)
    group.bench_function("profile_only_lookup_u32", |b| {
        b.iter(|| {
            let res = reader_compact.lookup_profile_u32(black_box(target_u32));
            black_box(res)
        });
    });

    // 3d. Direct threat predicate check (is_threat)
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
        use ipatlas_core::compiler::succinct::SuccinctIntervalTable;
        use ipatlas_core::models::{Ipv4Range, ProfileGen4};
        let ranges: Vec<Ipv4Range> = reader
            .ranges_ipv4()
            .iter()
            .map(|r| Ipv4Range::new(r.ip_from, r.ip_to, r.profile_id))
            .collect();
        let profiles: Vec<ProfileGen4> = reader.profiles().to_vec();
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
            family: ipatlas_core::RecordFamily::Compact,
            layout: ipatlas_core::StorageLayout::Soa,
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

    // 8. IPv6 Dual-Stack (128-bit) Evaluation (36B Ipv6Range)
    let (_dir_v6, bin_path_v6) = {
        let dir = tempdir().unwrap();
        let geo_v6_path = dir.path().join("bench_v6_geo.csv");
        let px_v6_path = dir.path().join("bench_v6_px.csv");
        let out_v6_bin = dir.path().join("bench_v6.bin");

        let mut geo_f = File::create(&geo_v6_path).unwrap();
        let mut px_f = File::create(&px_v6_path).unwrap();

        let base_v6: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0000;
        for i in 0..10_000u128 {
            let ip_from = base_v6 + (i << 64);
            let ip_to = ip_from | 0xffff_ffff_ffff_ffff;

            writeln!(
                geo_f,
                "{},{},US,United States,CA,Los Angeles,34.05,-118.24",
                ip_from, ip_to
            )
            .unwrap();

            if i % 4 == 0 {
                writeln!(
                    px_f,
                    "{},{},VPN,US,United States,CA,Los Angeles,Cloud Provider,host.com,DCH,13335,AS_NAME,2026-01-01,VPN",
                    ip_from, ip_to
                )
                .unwrap();
            }
        }

        let opts = CompilerOptions::new(&out_v6_bin)
            .geo_v6(Some(&geo_v6_path))
            .proxy_v6(Some(&px_v6_path));

        compile(opts).unwrap();
        (dir, out_v6_bin)
    };
    let reader_v6 = IpAtlasReader::open(&bin_path_v6).unwrap();
    let target_v6: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0000 + (5000 << 64) + 0x1234;

    group.bench_function("ipv6_standard_lookup_u128", |b| {
        b.iter(|| {
            let res = reader_v6.lookup_u128(black_box(target_v6));
            black_box(res)
        });
    });

    group.bench_function("ipv6_flags_lookup_u128", |b| {
        b.iter(|| {
            let res = reader_v6.lookup_flags_u128(black_box(target_v6));
            black_box(res)
        });
    });

    group.bench_function("ipv6_profile_lookup_u128", |b| {
        b.iter(|| {
            let res = reader_v6.lookup_profile_u128(black_box(target_v6));
            black_box(res)
        });
    });

    // 9. IPv6 Split-64 Compact (16B Ipv6RangeSplit64) Evaluation
    let (_dir_v6_cmp, bin_path_v6_cmp) = {
        let dir = tempdir().unwrap();
        let geo_v6_path = dir.path().join("bench_v6_cmp_geo.csv");
        let px_v6_path = dir.path().join("bench_v6_cmp_px.csv");
        let out_v6_bin = dir.path().join("bench_v6_cmp.bin");

        let mut geo_f = File::create(&geo_v6_path).unwrap();
        let mut px_f = File::create(&px_v6_path).unwrap();

        let base_v6: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0000;
        for i in 0..10_000u128 {
            let ip_from = base_v6 + (i << 64);
            let ip_to = ip_from | 0xffff_ffff_ffff_ffff;

            writeln!(
                geo_f,
                "{},{},US,United States,CA,Los Angeles,34.05,-118.24",
                ip_from, ip_to
            )
            .unwrap();

            if i % 4 == 0 {
                writeln!(
                    px_f,
                    "{},{},VPN,US,United States,CA,Los Angeles,Cloud Provider,host.com,DCH,13335,AS_NAME,2026-01-01,VPN",
                    ip_from, ip_to
                )
                .unwrap();
            }
        }

        let opt = ipatlas_core::OptimizationConfig {
            family: ipatlas_core::RecordFamily::Compact,
            split64_v6: true,
            ..Default::default()
        };

        let opts = CompilerOptions::new(&out_v6_bin)
            .geo_v6(Some(&geo_v6_path))
            .proxy_v6(Some(&px_v6_path))
            .optimization(opt);

        compile(opts).unwrap();
        (dir, out_v6_bin)
    };
    let reader_v6_cmp = IpAtlasReader::open(&bin_path_v6_cmp).unwrap();
    let target_v6_cmp: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0000 + (5000 << 64) + 0x1234;

    group.bench_function("ipv6_split64_compact_lookup_u128", |b| {
        b.iter(|| {
            let res = reader_v6_cmp.lookup_u128(black_box(target_v6_cmp));
            black_box(res)
        });
    });

    group.bench_function("ipv6_split64_flags_lookup_u128", |b| {
        b.iter(|| {
            let res = reader_v6_cmp.lookup_flags_u128(black_box(target_v6_cmp));
            black_box(res)
        });
    });

    group.bench_function("ipv6_split64_profile_lookup_u128", |b| {
        b.iter(|| {
            let res = reader_v6_cmp.lookup_profile_u128(black_box(target_v6_cmp));
            black_box(res)
        });
    });

    // 10. Branchless Eytzinger Array BFS Search Evaluation
    let eytzinger_v4 = {
        let raw_v4 = reader_compact.ranges_ipv4_compact();
        let mut ey = vec![ipatlas_core::models::Ipv4RangeCompact::default(); raw_v4.len() + 1];
        ipatlas_core::compiler::eytzinger::EytzingerSearch::build_eytzinger(raw_v4, &mut ey);
        ey
    };

    group.bench_function("eytzinger_branchless_lookup_u32", |b| {
        b.iter(|| {
            let res = ipatlas_core::compiler::eytzinger::EytzingerSearch::search_v4_compact(
                &eytzinger_v4,
                black_box(target_u32),
            );
            black_box(res)
        });
    });

    let eytzinger_v6 = {
        let raw_v6 = reader_v6_cmp.ranges_ipv6_compact();
        let mut ey = vec![ipatlas_core::models::Ipv6RangeSplit64::default(); raw_v6.len() + 1];
        ipatlas_core::compiler::eytzinger::EytzingerSearch::build_eytzinger(raw_v6, &mut ey);
        ey
    };
    let target_v6_hi = (target_v6_cmp >> 64) as u64;

    group.bench_function("eytzinger_branchless_lookup_v6_u64", |b| {
        b.iter(|| {
            let res = ipatlas_core::compiler::eytzinger::EytzingerSearch::search_v6_split64(
                &eytzinger_v6,
                black_box(target_v6_hi),
            );
            black_box(res)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_lookups);
criterion_main!(benches);
