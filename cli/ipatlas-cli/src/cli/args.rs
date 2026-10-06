use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ipatlas",
    about = "IPAtlas: Ultra-fast Zero-Copy Binary GeoIP & Proxy Threat Database Tool in Rust",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Compile CSV dataset(s) into IPAtlas Generation V5 binary and archives
    Compile(Box<CompileArgs>),
    /// Query an IPv4 or IPv6 address in IPAtlas database
    Lookup(LookupArgs),
    /// Inspect IPAtlas database header, CRC32, and metadata stats
    Info(InfoArgs),
    /// Convert an existing database binary to another layout (AoS <-> SoA)
    Convert(ConvertArgs),
    /// Measure lookup throughput and latency
    #[command(name = "bench", alias = "benchmark")]
    Bench(BenchArgs),
    /// Run lightweight HTTP Sidecar microservice with Prometheus metrics
    Serve(ServeArgs),
}

#[derive(Args)]
pub struct CompileArgs {
    /// Compilation mode: full, proxy, geo
    #[arg(short, long, default_value = "full")]
    pub mode: String,

    /// Feature preset: full, city, firewall, country, threats
    #[arg(long)]
    pub preset: Option<String>,

    /// Comma-separated feature flags: country,region,city,coords,isp,asn,threats
    #[arg(long)]
    pub features: Option<String>,

    /// Record family: standard (12B V4 / 36B V6) or compact (8B V4 / 36B V6)
    #[arg(long, default_value = "compact", aliases = ["tier"])]
    pub family: String,

    /// Physical memory layout: aos (Array of Structures) or soa (Structure of Arrays)
    #[arg(long, default_value = "aos")]
    pub layout: String,

    /// Optimization flags/level: -O0, -O1, -O2, -O3, or comma-separated rules (coalesce, lossy-coords, normalize-strings, compact-ranges, soa, aos)
    #[arg(short = 'O', long = "opt")]
    pub optimization: Vec<String>,

    /// Path to IPv4 IP2Location CSV (DB1, DB3, DB5, DB11, etc.)
    #[arg(long, aliases = ["db", "db5"])]
    pub geo: Option<PathBuf>,

    /// Path to IPv4 IP2Proxy CSV (PX1 - PX12)
    #[arg(long, aliases = ["px", "px10"])]
    pub proxy: Option<PathBuf>,

    /// Path to IPv6 IP2Location CSV (e.g. IP2LOCATION-LITE-DB5.IPV6.CSV)
    #[arg(long, aliases = ["db-v6", "geo-v6"])]
    pub geo_v6: Option<PathBuf>,

    /// Path to IPv6 IP2Proxy CSV (e.g. IP2PROXY-LITE-PX10.IPV6.CSV)
    #[arg(long, aliases = ["px-v6", "proxy-v6"])]
    pub proxy_v6: Option<PathBuf>,

    /// Path to MaxMind GeoLite2 City/Country Blocks CSV (e.g. GeoLite2-City-Blocks-IPv4.csv)
    #[arg(long = "maxmind-blocks", alias = "mm-blocks")]
    pub maxmind_blocks: Option<PathBuf>,

    /// Path to MaxMind GeoLite2 Locations CSV (e.g. GeoLite2-City-Locations-en.csv)
    #[arg(long = "maxmind-locations", alias = "mm-locations")]
    pub maxmind_locations: Option<PathBuf>,

    /// Output binary path (.bin)
    #[arg(short = 'o', long = "out")]
    pub out: PathBuf,

    /// Compress payload via embedded Zstandard frame (zstd-19) for ultra-compact disk storage
    #[arg(long = "embedded-zstd", alias = "zstd")]
    pub embedded_zstd: bool,

    /// Opt-in lossy 16-byte IPv6 Split-64 format (over-approximates sub-/64 intervals)
    #[arg(long = "split64-v6", aliases = ["split64", "lossy-v6"])]
    pub split64_v6: bool,
}

#[derive(Args)]
pub struct LookupArgs {
    /// Path to .bin database
    pub database: PathBuf,
    /// IP address to look up (IPv4 or IPv6)
    pub ip: String,
}

#[derive(Args)]
pub struct InfoArgs {
    /// Path to .bin database
    pub database: PathBuf,
}

#[derive(Args)]
pub struct ConvertArgs {
    /// Path to input .bin database
    pub input: PathBuf,
    /// Path to output .bin database
    pub output: PathBuf,
    /// Target layout: soa (Structure of Arrays) or aos (Array of Structures)
    #[arg(long, default_value = "soa")]
    pub layout: String,
}

#[derive(Args)]
pub struct BenchArgs {
    /// Path to .bin database
    pub database: PathBuf,
    /// Number of lookups to benchmark
    #[arg(short = 'n', long, default_value_t = 100_000)]
    pub count: usize,
}

#[derive(Args)]
pub struct ServeArgs {
    /// Path to .bin database
    #[arg(short = 'd', long = "database")]
    pub database: PathBuf,
    /// Listening TCP port
    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub port: u16,
    /// Bind address
    #[arg(short = 'b', long = "bind", default_value = "0.0.0.0")]
    pub bind: String,
}

pub fn format_num<T: std::fmt::Display>(n: T) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let bytes = s.as_bytes();
    let len = bytes.len();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 && b.is_ascii_digit() {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}
