//! Physical size comparison generator for all database generations:
//! - Gen 4 Standard (12B Range + 20B Profile)
//! - Gen 4.1 Compact (8B Range + 20B Profile)
//! - Gen 5 Dual-Stack (12B/36B + 20B)
//! - Gen 5 Embedded Zstd
//! - Gen 6 Standard (10B Range + 18B Profile)
//! - Gen 6 Compact Geo (7B Range + 12B Profile)
//! - Gen 6 Compact Edge (7B Range + 8B Profile)

use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use ipatlas_core::models::{
    Ipv4Range, Ipv4RangeCompact, Ipv4RangeV6, Ipv4RangeV6Compact, ProfileGen4, ProfileGen6,
    ProfileGen6Compact, ProfileGen6Edge,
};
use odd_int::I24;
use zerocopy::IntoBytes;

fn main() {
    let dir = tempdir().unwrap();
    let csv_geo = dir.path().join("geo.csv");
    let csv_proxy = dir.path().join("proxy.csv");

    let num_records = 50_000;
    println!(
        "Generating benchmark dataset with {} IPv4 ranges...",
        num_records
    );

    let mut geo_f = File::create(&csv_geo).unwrap();
    let mut proxy_f = File::create(&csv_proxy).unwrap();

    let mut curr_ip = 16_777_216u32; // 1.0.0.0
    for i in 0..num_records {
        let step = 256;
        let ip_from = curr_ip;
        let ip_to = curr_ip + step - 1;
        curr_ip = ip_to + 1;

        let city = match i % 5 {
            0 => "Los Angeles",
            1 => "New York",
            2 => "Frankfurt am Main",
            3 => "Tokyo",
            _ => "Singapore",
        };
        let region = match i % 4 {
            0 => "California",
            1 => "New York",
            2 => "Hesse",
            _ => "Kanto",
        };
        let country = match i % 5 {
            0 | 1 => "US",
            2 => "DE",
            3 => "JP",
            _ => "SG",
        };

        writeln!(
            geo_f,
            "{},{},{},{},{},{},34.05,-118.24",
            ip_from, ip_to, country, country, region, city
        )
        .unwrap();

        if i % 3 == 0 {
            writeln!(
                proxy_f,
                "{},{},VPN,{},{},{},{},Cloud Provider,host.com,DCH,13335,AS_NAME,2026-01-01,VPN",
                ip_from, ip_to, country, country, region, city
            )
            .unwrap();
        }
    }

    let out_gen4_std = dir.path().join("db_gen4_standard.bin");
    let out_gen4_compact = dir.path().join("db_gen4_compact.bin");
    let out_gen5_zstd = dir.path().join("db_gen5_embedded_zstd.bin");

    // 1. Compile Gen 4 Standard
    ipatlas_core::compile(
        ipatlas_core::CompilerOptions::new(&out_gen4_std)
            .geo(Some(&csv_geo))
            .proxy(Some(&csv_proxy))
            .optimization(ipatlas_core::OptimizationConfig {
                compact_ranges: false,
                ..Default::default()
            }),
    )
    .unwrap();

    // 2. Compile Gen 4.1 Compact
    ipatlas_core::compile(
        ipatlas_core::CompilerOptions::new(&out_gen4_compact)
            .geo(Some(&csv_geo))
            .proxy(Some(&csv_proxy))
            .optimization(ipatlas_core::OptimizationConfig {
                compact_ranges: true,
                ..Default::default()
            }),
    )
    .unwrap();

    // 3. Compile Gen 5 Embedded Zstd
    ipatlas_core::compile(
        ipatlas_core::CompilerOptions::new(&out_gen5_zstd)
            .geo(Some(&csv_geo))
            .proxy(Some(&csv_proxy))
            .embedded_zstd(true)
            .optimization(ipatlas_core::OptimizationConfig {
                compact_ranges: true,
                ..Default::default()
            }),
    )
    .unwrap();

    // 4. Physical Gen 6 Containers
    // Collect unique strings
    let string_blob = b"US\0DE\0JP\0SG\0Los Angeles\0New York\0Frankfurt am Main\0Tokyo\0Singapore\0California\0Hesse\0Kanto\0Cloud Provider\0";
    let num_profiles = 500usize;

    // Gen 6 Standard (10B range + 18B profile + string pool)
    let out_gen6_std = dir.path().join("db_gen6_standard.bin");
    {
        let mut f = File::create(&out_gen6_std).unwrap();
        // Magic header: 16 bytes
        f.write_all(b"STDC_GEN6_STD\0\0\0").unwrap();
        for i in 0..num_records {
            let r = Ipv4RangeV6::new(i * 256, i * 256 + 255, (i % num_profiles as u32) as i16);
            f.write_all(r.as_bytes()).unwrap();
        }
        for i in 0..num_profiles {
            let p = ProfileGen6::new(
                13335,
                1,
                *b"US",
                3405,
                -11824,
                I24::from_i64(14).unwrap(),
                I24::from_i64(37).unwrap(),
            );
            f.write_all(p.as_bytes()).unwrap();
        }
        f.write_all(string_blob).unwrap();
    }

    // Gen 6 Compact Geo (7B range + 12B profile + string pool)
    let out_gen6_compact_geo = dir.path().join("db_gen6_compact_geo.bin");
    {
        let mut f = File::create(&out_gen6_compact_geo).unwrap();
        f.write_all(b"STDC_GEN6_GEO\0\0\0").unwrap();
        for i in 0..num_records {
            let r = Ipv4RangeV6Compact::new(
                i * 256,
                I24::from_i64((i % num_profiles as u32) as i64).unwrap(),
            );
            f.write_all(r.as_bytes()).unwrap();
        }
        for i in 0..num_profiles {
            let p = ProfileGen6Compact::new(13335, 1, *b"US", 3, 9);
            f.write_all(p.as_bytes()).unwrap();
        }
        f.write_all(string_blob).unwrap();
    }

    // Gen 6 Compact Edge (7B range + 8B profile)
    let out_gen6_compact_edge = dir.path().join("db_gen6_compact_edge.bin");
    {
        let mut f = File::create(&out_gen6_compact_edge).unwrap();
        f.write_all(b"STDC_GEN6_EDGE\0\0").unwrap();
        for i in 0..num_records {
            let r = Ipv4RangeV6Compact::new(
                i * 256,
                I24::from_i64((i % num_profiles as u32) as i64).unwrap(),
            );
            f.write_all(r.as_bytes()).unwrap();
        }
        for _ in 0..num_profiles {
            let p = ProfileGen6Edge::new(13335, 1, *b"US");
            f.write_all(p.as_bytes()).unwrap();
        }
    }

    // Read and format file sizes
    let s_g4_std = std::fs::metadata(&out_gen4_std).unwrap().len();
    let s_g4_cmp = std::fs::metadata(&out_gen4_compact).unwrap().len();
    let s_g5_zstd = std::fs::metadata(&out_gen5_zstd).unwrap().len();
    let s_g6_std = std::fs::metadata(&out_gen6_std).unwrap().len();
    let s_g6_geo = std::fs::metadata(&out_gen6_compact_geo).unwrap().len();
    let s_g6_edge = std::fs::metadata(&out_gen6_compact_edge).unwrap().len();

    println!("\n=========================================================================================");
    println!(
        "                       DATABASE BINARY FILE SIZES ({} RECORDS)                    ",
        num_records
    );
    println!(
        "========================================================================================="
    );
    println!("Format Variant                          File Size (Bytes)    File Size (KB)    Savings vs Gen4");
    println!(
        "-----------------------------------------------------------------------------------------"
    );
    println!(
        "Gen 4 Standard (12B Range + 20B Profile)   {:>10} B       {:>8.2} KB           Baseline",
        s_g4_std,
        s_g4_std as f64 / 1024.0
    );
    println!(
        "Gen 4.1 Compact (8B Range + 20B Profile)   {:>10} B       {:>8.2} KB           -{:.1}%",
        s_g4_cmp,
        s_g4_cmp as f64 / 1024.0,
        (1.0 - (s_g4_cmp as f64 / s_g4_std as f64)) * 100.0
    );
    println!(
        "Gen 6 Standard (10B Range + 18B Profile)   {:>10} B       {:>8.2} KB           -{:.1}%",
        s_g6_std,
        s_g6_std as f64 / 1024.0,
        (1.0 - (s_g6_std as f64 / s_g4_std as f64)) * 100.0
    );
    println!(
        "Gen 6 Compact Geo (7B Range + 12B Profile) {:>10} B       {:>8.2} KB           -{:.1}%",
        s_g6_geo,
        s_g6_geo as f64 / 1024.0,
        (1.0 - (s_g6_geo as f64 / s_g4_std as f64)) * 100.0
    );
    println!(
        "Gen 6 Compact Edge (7B Range + 8B Profile) {:>10} B       {:>8.2} KB           -{:.1}%",
        s_g6_edge,
        s_g6_edge as f64 / 1024.0,
        (1.0 - (s_g6_edge as f64 / s_g4_std as f64)) * 100.0
    );
    println!(
        "Gen 5 Embedded Zstd (Compressed Archive)   {:>10} B       {:>8.2} KB           -{:.1}%",
        s_g5_zstd,
        s_g5_zstd as f64 / 1024.0,
        (1.0 - (s_g5_zstd as f64 / s_g4_std as f64)) * 100.0
    );
    println!("=========================================================================================\n");
}
