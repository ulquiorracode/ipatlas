use std::path::PathBuf;
use std::time::Instant;

use clap::{Args, Parser, Subcommand};
use ipatlas::{
    compile, CompilerOptions, FeatureMask, IpAtlasReader, OptimizationConfig, Preset,
    RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD,
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
    /// Compile CSV dataset(s) into IPAtlas binary and archives
    Compile(CompileArgs),
    /// Query an IP address in IPAtlas database
    Lookup(LookupArgs),
    /// Inspect IPAtlas database header and metadata stats
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

    /// Memory layout: standard (12B, V4) or compact (8B, V4.1)
    #[arg(long, default_value = "standard")]
    layout: String,

    /// Optimization flags/level: -O0, -O1, -O2, -O3, or comma-separated rules (coalesce, lossy-coords, normalize-strings, compact-ranges)
    #[arg(short = 'O', long = "opt")]
    optimization: Vec<String>,

    /// Path to IP2Location CSV (DB1, DB3, DB5, DB11, etc.)
    #[arg(long, aliases = ["db", "db5"])]
    geo: Option<PathBuf>,

    /// Path to IP2Proxy CSV (PX1 - PX12)
    #[arg(long, aliases = ["px", "px10"])]
    proxy: Option<PathBuf>,

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
    /// IPv4 address to look up
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
        Commands::Compile(args) => run_compile(args)?,
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

    let geo_path = args.geo.as_deref();
    let proxy_path = args.proxy.as_deref();

    if geo_path.is_none() && proxy_path.is_none() {
        anyhow::bail!("Compilation requires at least --geo or --proxy dataset input");
    }

    let layout_label = if opt_config.compact_ranges {
        "V4.1 Compact (8B)"
    } else {
        "V4 Standard (12B)"
    };
    println!(
        "Compiling IPAtlas Database [Layout: {} | Feature Mask: {:#06x}]...",
        layout_label, feature_mask.0
    );
    println!("Optimization Configuration: {:?}", opt_config);

    let opts = CompilerOptions {
        geo_path,
        proxy_path,
        output_path: &args.out,
        features: feature_mask,
        opt: opt_config,
        write_gz: !args.no_gz,
        write_zst: !args.no_zst,
    };

    let stats = compile(opts)?;

    let raw_mb = (stats.raw_size as f64) / (1024.0 * 1024.0);
    let gz_msg = stats
        .gz_size
        .map(|s| format!(" | GZ: {:.1} MB", (s as f64) / (1024.0 * 1024.0)))
        .unwrap_or_default();
    let zst_msg = stats
        .zst_size
        .map(|s| format!(" | ZST: {:.1} MB", (s as f64) / (1024.0 * 1024.0)))
        .unwrap_or_default();

    let layout_msg = if stats.is_compact {
        if stats.records != stats.original_records {
            format!(
                " [Layout: V4.1 Compact (8B) - {} ranges split into {} records]",
                format_num(stats.original_records),
                format_num(stats.records)
            )
        } else {
            " [Layout: V4.1 Compact (8B)]".to_string()
        }
    } else {
        " [Layout: V4 Standard (12B)]".to_string()
    };

    println!(
        "Successfully compiled {} intervals ({} profiles) in {:.2}s | Binary: {:.1} MB{}{}{}",
        format_num(stats.records),
        format_num(stats.profiles),
        stats.elapsed_secs,
        raw_mb,
        gz_msg,
        zst_msg,
        layout_msg
    );

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
        println!("Flags:       {:#05x}", rec.flags.0);
        println!("  Datacenter:  {}", rec.flags.is_datacenter());
        println!("  Proxy / VPN: {}", rec.flags.is_proxy());
        println!("  Botnet:      {}", rec.flags.is_botnet());
        println!("  Spam:        {}", rec.flags.is_spam());
        println!("  Mobile:      {}", rec.flags.is_mobile());
        println!("  Residential: {}", rec.flags.is_residential());
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

    let (version_name, rec_size) = if reader.is_compact() {
        (
            "IPAtlas Version 4.1 (V4-Compact, 8B/range)",
            RECORD_SIZE_V4_COMPACT,
        )
    } else {
        (
            "IPAtlas Version 4 (Standard, 12B/range)",
            RECORD_SIZE_V4_STANDARD,
        )
    };

    println!("Database:       {:?}", args.database);
    println!("Format:         {}", version_name);
    println!("Records:        {}", format_num(reader.len()));
    println!("Record Size:    {} bytes", rec_size);
    println!("Profiles:       {}", format_num(reader.profile_count()));
    println!("Indexed Cities: {}", format_num(reader.city_count()));
    println!("Indexed Regions:{}", format_num(reader.region_count()));
    println!("Indexed ISPs:   {}", format_num(reader.isp_count()));
    println!("File Size:      {:.2} MB", size_mb);

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
