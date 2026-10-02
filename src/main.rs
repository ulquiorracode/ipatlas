use std::path::PathBuf;
use std::time::Instant;

use clap::{Args, Parser, Subcommand};
use ipatlas::{
    compile, CompilerOptions, FeatureMask, IpAtlasReader, OptimizationConfig, Preset,
    RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD, RECORD_SIZE_V6,
};

#[derive(Parser)]
#[command(
    name = "ipatlas",
    about = "IPAtlas: Ultra-fast Zero-Copy Binary GeoIP & Proxy Threat Database Tool in Rust",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile CSV dataset(s) into IPAtlas Generation V5 binary and archives
    Compile(Box<CompileArgs>),
    /// Query an IPv4 or IPv6 address in IPAtlas database
    Lookup(LookupArgs),
    /// Inspect IPAtlas database header, CRC32, and metadata stats
    Info(InfoArgs),
    /// Measure lookup throughput and latency
    #[command(name = "bench", alias = "benchmark")]
    Bench(BenchArgs),
}

#[derive(Args)]
struct CompileArgs {
    /// Compilation mode: full, proxy, geo
    #[arg(short, long, default_value = "full")]
    mode: String,

    /// Feature preset: full, city, firewall, country, threats
    #[arg(long)]
    preset: Option<String>,

    /// Comma-separated feature flags: country,region,city,coords,isp,asn,threats
    #[arg(long)]
    features: Option<String>,

    /// Memory layout: standard (12B V4 / 36B V6) or compact (8B V4 / 36B V6)
    #[arg(long, default_value = "standard")]
    layout: String,

    /// Optimization flags/level: -O0, -O1, -O2, -O3, or comma-separated rules (coalesce, lossy-coords, normalize-strings, compact-ranges)
    #[arg(short = 'O', long = "opt")]
    optimization: Vec<String>,

    /// Path to IPv4 IP2Location CSV (DB1, DB3, DB5, DB11, etc.)
    #[arg(long, aliases = ["db", "db5"])]
    geo: Option<PathBuf>,

    /// Path to IPv4 IP2Proxy CSV (PX1 - PX12)
    #[arg(long, aliases = ["px", "px10"])]
    proxy: Option<PathBuf>,

    /// Path to IPv6 IP2Location CSV (e.g. IP2LOCATION-LITE-DB5.IPV6.CSV)
    #[arg(long, aliases = ["db-v6", "geo-v6"])]
    geo_v6: Option<PathBuf>,

    /// Path to IPv6 IP2Proxy CSV (e.g. IP2PROXY-LITE-PX10.IPV6.CSV)
    #[arg(long, aliases = ["px-v6", "proxy-v6"])]
    proxy_v6: Option<PathBuf>,

    /// Output binary path (.bin)
    #[arg(short = 'o', long = "out")]
    out: PathBuf,

    /// Skip .gz compression
    #[arg(long)]
    no_gz: bool,

    /// Skip .zst compression
    #[arg(long)]
    no_zst: bool,
}

#[derive(Args)]
struct LookupArgs {
    /// Path to .bin database
    database: PathBuf,
    /// IP address to look up (IPv4 or IPv6)
    ip: String,
}

#[derive(Args)]
struct InfoArgs {
    /// Path to .bin database
    database: PathBuf,
}

#[derive(Args)]
struct BenchArgs {
    /// Path to .bin database
    database: PathBuf,
    /// Number of lookups to benchmark
    #[arg(short = 'n', long, default_value_t = 100_000)]
    count: usize,
}

fn format_num<T: std::fmt::Display>(n: T) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let bytes = s.as_bytes();
    let len = bytes.len();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) && b.is_ascii_digit() {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile(args) => run_compile(*args)?,
        Commands::Lookup(args) => run_lookup(args)?,
        Commands::Info(args) => run_info(args)?,
        Commands::Bench(args) => run_bench(args)?,
    }

    Ok(())
}

fn run_compile(args: CompileArgs) -> anyhow::Result<()> {
    let feature_mask = if let Some(preset_name) = &args.preset {
        match Preset::from_str_name(preset_name) {
            Some(p) => p.feature_mask(),
            None => anyhow::bail!(
                "Unknown preset: '{}'. Available: full, city, firewall, country, threats",
                preset_name
            ),
        }
    } else if let Some(feat_str) = &args.features {
        FeatureMask::parse_csv(feat_str).map_err(|e| anyhow::anyhow!(e))?
    } else {
        match args.mode.to_lowercase().as_str() {
            "proxy" => FeatureMask(
                FeatureMask::COUNTRY
                    | FeatureMask::CITY
                    | FeatureMask::ISP
                    | FeatureMask::ASN
                    | FeatureMask::THREATS,
            ),
            "geo" => FeatureMask(
                FeatureMask::COUNTRY
                    | FeatureMask::REGION
                    | FeatureMask::CITY
                    | FeatureMask::COORDS,
            ),
            _ => FeatureMask::default(),
        }
    };

    // Optimization flags
    let mut opt_config = OptimizationConfig::default();
    if args.layout.to_lowercase() == "compact" || args.layout.to_lowercase() == "v4.1" {
        opt_config.compact_ranges = true;
    }

    for opt_arg in &args.optimization {
        opt_config
            .parse_arg(opt_arg)
            .map_err(|e| anyhow::anyhow!(e))?;
    }

    let mut geo_v4 = args.geo.as_deref();
    let mut geo_v6 = args.geo_v6.as_deref();
    let mut proxy_v4 = args.proxy.as_deref();
    let mut proxy_v6 = args.proxy_v6.as_deref();

    // Auto-detect IPv6 from file name if user passed v6 file in --geo or --proxy
    if geo_v6.is_none() {
        if let Some(p) = geo_v4 {
            if p.to_string_lossy().to_uppercase().contains("IPV6") {
                geo_v6 = Some(p);
                geo_v4 = None;
            }
        }
    }
    if proxy_v6.is_none() {
        if let Some(p) = proxy_v4 {
            if p.to_string_lossy().to_uppercase().contains("IPV6") {
                proxy_v6 = Some(p);
                proxy_v4 = None;
            }
        }
    }

    if geo_v4.is_none() && proxy_v4.is_none() && geo_v6.is_none() && proxy_v6.is_none() {
        anyhow::bail!("Compilation requires at least one dataset input (--geo, --proxy, --geo-v6, --proxy-v6)");
    }

    let layout_label = if opt_config.compact_ranges {
        "Generation V5 Compact (8B V4 / 36B V6)"
    } else {
        "Generation V5 Standard (12B V4 / 36B V6)"
    };
    println!(
        "Compiling IPAtlas Database [Layout: {} | Feature Mask: {:#06x}]...",
        layout_label, feature_mask.0
    );
    println!("Optimization Configuration: {:?}", opt_config);

    let opts = CompilerOptions {
        geo_path: geo_v4,
        proxy_path: proxy_v4,
        geo_v6_path: geo_v6,
        proxy_v6_path: proxy_v6,
        output_path: &args.out,
        features: feature_mask,
        opt: opt_config,
        write_gz: !args.no_gz,
        write_zst: !args.no_zst,
    };

    let stats = compile(opts)?;

    for warn in &stats.warnings {
        eprintln!("Warning: {}", warn);
    }

    let raw_mb = (stats.raw_size as f64) / (1024.0 * 1024.0);
    let gz_msg = stats
        .gz_size
        .map(|s| format!(" | GZ: {:.1} MB", (s as f64) / (1024.0 * 1024.0)))
        .unwrap_or_default();
    let zst_msg = stats
        .zst_size
        .map(|s| format!(" | ZST: {:.1} MB", (s as f64) / (1024.0 * 1024.0)))
        .unwrap_or_default();

    println!(
        "Successfully compiled {} intervals (V4: {}, V6: {}, {} profiles) in {:.2}s | Binary: {:.1} MB{}{}",
        format_num(stats.records),
        format_num(stats.records_v4),
        format_num(stats.records_v6),
        format_num(stats.profiles),
        stats.elapsed_secs,
        raw_mb,
        gz_msg,
        zst_msg
    );
    println!("Checksum CRC32: {:#010x}", stats.crc32);

    Ok(())
}

fn run_lookup(args: LookupArgs) -> anyhow::Result<()> {
    if !args.database.exists() {
        anyhow::bail!("Database file not found: {:?}", args.database);
    }

    let reader = IpAtlasReader::open(&args.database)?;
    let t0 = Instant::now();
    let res = reader.lookup_str(&args.ip);
    let dt = t0.elapsed();
    let dt_us = dt.as_secs_f64() * 1_000_000.0;

    if let Some(rec) = res {
        println!("IP:          {}", rec.ip);
        println!("Type:        {}", if rec.is_v6 { "IPv6" } else { "IPv4" });
        println!("Range:       {}", rec.range_str());
        println!("Country:     {}", rec.country);
        println!(
            "Region:      {}",
            if rec.region.is_empty() {
                "N/A"
            } else {
                &rec.region
            }
        );
        println!(
            "City:        {}",
            if rec.city.is_empty() {
                "N/A"
            } else {
                &rec.city
            }
        );
        println!("Coordinates: {:.2}, {:.2}", rec.latitude, rec.longitude);
        println!(
            "ISP:         {}",
            if rec.isp.is_empty() { "N/A" } else { &rec.isp }
        );
        println!(
            "ASN:         {}",
            if rec.asn != 0 {
                format!("AS{}", rec.asn)
            } else {
                "N/A".to_string()
            }
        );
        println!("Flags:       {:#06x}", rec.flags.0);
        if rec.flags.is_proxy() {
            println!("  [PROXY DETECTED]");
            if rec.flags.is_vpn() {
                println!("  - VPN:         true");
            }
            if rec.flags.is_tor() {
                println!("  - TOR:         true");
            }
            if rec.flags.is_datacenter() {
                println!("  - DCH (DataCenter): true");
            }
            if rec.flags.is_pub() {
                println!("  - PUB (Public Proxy): true");
            }
            if rec.flags.is_web() {
                println!("  - WEB (Web Proxy):    true");
            }
            if rec.flags.is_ses() {
                println!("  - SES (Search Engine Spider): true");
            }
            if rec.flags.is_res() {
                println!("  - RES (Residential Proxy):   true");
            }
            if rec.flags.is_cpn() {
                println!("  - CPN (Consumer Privacy Net): true");
            }
            if rec.flags.is_epn() {
                println!("  - EPN (Enterprise Private Net): true");
            }
        }
        if rec.flags.is_botnet() {
            println!("  - Threat: BOTNET");
        }
        if rec.flags.is_spam() {
            println!("  - Threat: SPAM");
        }
        if rec.flags.is_scanner() {
            println!("  - Threat: PORT SCANNER");
        }
        if rec.flags.is_mobile() {
            println!("  - Network: MOBILE / 3G / 4G / 5G");
        }
        if rec.flags.is_cdn() {
            println!("  - Network: CDN");
        }

        println!("Lookup Time: {:.2} µs ({} ns)", dt_us, dt.as_nanos());
    } else {
        println!(
            "IP {} not found in database (took {:.2} µs)",
            args.ip, dt_us
        );
    }

    Ok(())
}

fn run_info(args: InfoArgs) -> anyhow::Result<()> {
    if !args.database.exists() {
        anyhow::bail!("Database file not found: {:?}", args.database);
    }

    let file_size = std::fs::metadata(&args.database)?.len();
    let size_mb = (file_size as f64) / (1024.0 * 1024.0);
    let reader = IpAtlasReader::open(&args.database)?;

    let is_v5 = reader.version() >= 5;
    let version_name = match reader.version() {
        5 => "Generation V5 (Standard Dual-Stack: 12B V4 / 36B V6)",
        0x0501 => "Generation V5 (Compact Dual-Stack: 8B V4 / 36B V6)",
        4 => "Generation V4 (Standard IPv4: 12B/range)",
        0x0401 => "Generation V4 (Compact IPv4: 8B/range)",
        v => Box::leak(format!("Version {:#06x}", v).into_boxed_str()),
    };

    println!("Database:       {:?}", args.database);
    println!("Format:         {}", version_name);
    println!("Total Records:  {}", format_num(reader.len()));
    println!("  IPv4 Records: {}", format_num(reader.len_v4()));
    println!("  IPv6 Records: {}", format_num(reader.len_v6()));
    if reader.len_v4() > 0 {
        let v4_sz = if reader.is_compact() {
            RECORD_SIZE_V4_COMPACT
        } else {
            RECORD_SIZE_V4_STANDARD
        };
        println!("IPv4 Size:      {} bytes/record", v4_sz);
    }
    if is_v5 {
        println!("IPv6 Size:      {} bytes/record", RECORD_SIZE_V6);
    }
    println!("Profiles:       {}", format_num(reader.profile_count()));
    println!("Indexed Cities: {}", format_num(reader.city_count()));
    println!("Indexed Regions:{}", format_num(reader.region_count()));
    println!("Indexed ISPs:   {}", format_num(reader.isp_count()));
    println!("File Size:      {:.2} MB", size_mb);

    if let Some(stored_crc) = reader.crc32() {
        let crc_res = reader.validate_checksum();
        match crc_res {
            Ok(()) => println!("Checksum:       OK ({:#010x})", stored_crc),
            Err(e) => println!("Checksum:       FAIL: {}", e),
        }
    } else {
        println!("Checksum:       N/A (Generation V4 does not store CRC32)");
    }

    Ok(())
}

fn run_bench(args: BenchArgs) -> anyhow::Result<()> {
    if !args.database.exists() {
        anyhow::bail!("Database file not found: {:?}", args.database);
    }

    println!(
        "Benchmarking {} lookups against {:?}...",
        format_num(args.count),
        args.database
    );
    let reader = IpAtlasReader::open(&args.database)?;

    if reader.is_empty() {
        anyhow::bail!("Cannot benchmark empty database");
    }

    // Generate pseudo-random IPs deterministically
    let mut ip_seed: u32 = 0x811c9dc5;
    let mut test_ips = Vec::with_capacity(args.count);
    for _ in 0..args.count {
        ip_seed = ip_seed.wrapping_mul(1664525).wrapping_add(1013904223);
        test_ips.push(ip_seed);
    }

    let t0 = Instant::now();
    let mut hits = 0;
    for &ip in &test_ips {
        if reader.lookup_u32(ip).is_some() {
            hits += 1;
        }
    }
    let total_time = t0.elapsed();
    let total_secs = total_time.as_secs_f64();
    let qps = (args.count as f64) / total_secs;
    let avg_ns = (total_time.as_nanos() as f64) / (args.count as f64);

    println!("Completed in {:.3}s", total_secs);
    println!("Throughput:      {} queries/sec", format_num(qps as u64));
    println!(
        "Average Latency: {:.1} ns/query ({:.3} µs)",
        avg_ns,
        avg_ns / 1000.0
    );
    println!(
        "Hit Rate:        {}/{} ({:.1}%)",
        format_num(hits),
        format_num(args.count),
        (hits as f64 / args.count as f64) * 100.0
    );

    Ok(())
}
