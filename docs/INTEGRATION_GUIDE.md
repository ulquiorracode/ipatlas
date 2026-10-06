# IPAtlas Integration & Deployment Guide

This guide describes real-world deployment patterns, web framework integration, zero-downtime hot reloading, and optimization strategies for integrating **IPAtlas** into production Rust services.

---

## 1. Quick Start

Add IPAtlas to your service's `Cargo.toml`:

```toml
[dependencies]
ipatlas = { version = "0.10.0", default-features = false }
```

### Basic Lookup (IPv4 & IPv6)

```rust
use ipatlas::IpAtlasReader;
use std::net::IpAddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Zero-copy mmap initialization (sub-millisecond startup, zero memory overhead)
    let reader = IpAtlasReader::open("data/ipatlas.bin")?;

    // 1. Borrowed zero-allocation view (recommended for request-response loops)
    if let Some(record) = reader.lookup_ref("8.8.8.8".parse::<IpAddr>()?) {
        println!("Country: {}", record.country);
        println!("City: {}", record.city);
        println!("Is Threat: {}", record.flags.is_threat());
        println!("Is Datacenter: {}", record.flags.is_datacenter());
    }

    // 2. High-throughput firewall mode (flags only, 14–18 ns)
    let ip_u32 = u32::from(std::net::Ipv4Addr::new(1, 1, 1, 1));
    if let Some(flags) = reader.lookup_flags_u32(ip_u32) {
        if flags.is_proxy() || flags.is_tor() {
            println!("Block suspicious IP!");
        }
    }

    Ok(())
}
```

---

## 2. Web Framework Integration

`IpAtlasReader` is thread-safe (`Send + Sync`) and designed to be shared across all request worker threads via `std::sync::Arc`.

### 2.1 Axum Integration

```rust
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use ipatlas::IpAtlasReader;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    geo: Arc<IpAtlasReader>,
}

#[derive(Serialize)]
struct GeoResponse<'a> {
    ip: String,
    country: &'a str,
    city: &'a str,
    asn: u32,
    is_vpn: bool,
}

async fn lookup_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<GeoResponse<'static>>, StatusCode> {
    let record = state.geo.lookup_ref(addr.ip()).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(GeoResponse {
        ip: addr.ip().to_string(),
        country: record.country,
        city: record.city,
        asn: record.asn,
        is_vpn: record.flags.is_vpn(),
    }))
}

#[tokio::main]
async fn main() {
    let reader = Arc::new(IpAtlasReader::open("data/ipatlas.bin").expect("Failed to open DB"));
    let state = AppState { geo: reader };

    let app = Router::new()
        .route("/geo", get(lookup_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
```

### 2.2 Actix-web Integration

```rust
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use ipatlas::IpAtlasReader;
use std::net::IpAddr;
use std::sync::Arc;

async fn geo_lookup(
    reader: web::Data<Arc<IpAtlasReader>>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    let ip_str = query.get("ip").cloned().unwrap_or_else(|| "127.0.0.1".into());
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        if let Some(record) = reader.lookup_ref(ip) {
            return HttpResponse::Ok().json(serde_json::json!({
                "country": record.country,
                "city": record.city,
                "is_threat": record.flags.is_threat(),
            }));
        }
    }
    HttpResponse::NotFound().finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let reader = Arc::new(IpAtlasReader::open("data/ipatlas.bin").expect("Failed to open DB"));

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(reader.clone()))
            .route("/geo", web::get().to(geo_lookup))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
```

---

## 3. Zero-Downtime Hot Reloading

Because IPAtlas uses read-only memory mapping, live databases can be atomically replaced in memory without dropping connections, locking threads, or pausing incoming traffic.

Use `arc-swap` for lock-free pointer swapping:

```rust
use arc_swap::ArcSwap;
use ipatlas::IpAtlasReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct HotReloadGeo {
    path: PathBuf,
    reader: ArcSwap<IpAtlasReader>,
}

impl HotReloadGeo {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let p = path.as_ref().to_path_buf();
        let initial = Arc::new(IpAtlasReader::open(&p)?);
        Ok(Self {
            path: p,
            reader: ArcSwap::from(initial),
        })
    }

    /// Access current reader for zero-allocation lookups
    #[inline(always)]
    pub fn load(&self) -> arc_swap::Guard<Arc<IpAtlasReader>> {
        self.reader.load()
    }

    /// Atomically swaps the active database with the updated binary on disk.
    /// Inflight requests complete gracefully on the old mapping.
    pub fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
        let new_reader = Arc::new(IpAtlasReader::open(&self.path)?);
        self.reader.store(new_reader);
        Ok(())
    }
}
```

---

## 4. Selecting Layout Presets

When compiling `.bin` files via the IPAtlas CLI, choose the preset matching your workload:

```bash
# 1. Edge Firewall / WAF Mode (Minimal RAM, Max throughput)
# Drops coordinates and string tables, coalesces adjacent CIDRs
ipatlas compile -g IP2LOCATION-LITE-DB5.CSV -p IP2PROXY-LITE-PX10.CSV \
  --preset firewall \
  -o dist/firewall.bin

# 2. Country-Only Routing / Compliance Mode
# Preserves ISO 2-letter codes, strips cities/ISPs
ipatlas compile -g IP2LOCATION-LITE-DB5.CSV \
  --preset country \
  -o dist/country.bin

# 3. Full Precision Dual-Stack Production Database (Compact AoS)
# Packs IPv4 into 8-byte intervals, IPv6 into 16-byte Split-64 intervals
ipatlas compile \
  -g IP2LOCATION-LITE-DB5.CSV \
  -p IP2PROXY-LITE-PX10.CSV \
  --geo-v6 IP2LOCATION-LITE-DB5.IPV6.CSV \
  --proxy-v6 IP2PROXY-LITE-PX10.IPV6.CSV \
  --layout compact \
  -o dist/production_compact.bin
```

### Decision Matrix

| Deployment Target | Recommended Preset / Flags | RAM Impact | Query Latency | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Reverse Proxy / Envoy / Cloudflare Worker** | `--preset firewall` | **$\sim 8$ MB** | **$\le 15$ ns** | Threats, Proxies, VPNs, Tor detection |
| **Geo-DNS / Regional Traffic Steering** | `--preset country` | **$\sim 12$ MB** | **$\le 25$ ns** | ISO country resolution |
| **E-Commerce / Fraud Detection** | `--preset full --layout compact` | **$\sim 41$ MB** | **$\sim 60$ ns** | Full City, Region, ISP, Lat/Lon, Threat flags |
| **Low-Memory Routers / IoT (16MB RAM)** | `--preset succinct` *(Tier 3)* | **$\sim 18$ MB** | **$\sim 350$ ns** | Elias-Fano Bitvector Shannon limit |

---

## 5. Performance Best Practices

1. **Prefer `lookup_ref` over `lookup`**:
   `lookup_ref()` returns `GeoRecordRef<'_>`, which borrows strings directly from the mmap table. `lookup()` clones strings into owned `String` instances on the heap.
2. **Use fast paths when full resolution is unneeded**:
   - `lookup_flags_u32(ip)` / `lookup_flags(ip)`: **14–18 ns** (threat bitmask only).
   - `lookup_country_code_u32(ip)`: **20–30 ns** (2-letter string slice, no city/region decoding).
   - `is_threat(ip)` / `is_proxy(ip)` / `is_datacenter(ip)`: single-cycle boolean checks.
3. **OS Kernel Warmup (`warmup()`)**:
   Call `reader.warmup()` after `open()` to issue `madvise(MADV_WILLNEED)` on Linux/Unix systems, faulting range tables into physical RAM pages before traffic arrives.
