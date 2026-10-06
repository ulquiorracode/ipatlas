use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ipatlas_core::IpAtlasReader;

use crate::cli::args::ServeArgs;

struct Metrics {
    total_requests: AtomicU64,
    lookup_requests: AtomicU64,
    threats_detected: AtomicU64,
    errors: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            lookup_requests: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

pub fn run_serve(args: ServeArgs) -> anyhow::Result<()> {
    if !args.database.exists() {
        anyhow::bail!("Database file not found: {:?}", args.database);
    }

    println!("Initializing IPAtlas Sidecar / Microservice...");
    let reader = Arc::new(IpAtlasReader::open(&args.database)?);
    println!("  Database: {:?}", args.database);
    println!("  Listening: http://{}:{}", args.bind, args.port);
    println!("  Endpoints:");
    println!("    GET /lookup/<ip>  - JSON IP geolocation & threat intelligence");
    println!("    GET /healthz      - Liveness / Readiness check");
    println!("    GET /metrics      - Prometheus formatted telemetry");

    let listener = TcpListener::bind(format!("{}:{}", args.bind, args.port))?;
    let metrics = Arc::new(Metrics::new());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let r = Arc::clone(&reader);
                let m = Arc::clone(&metrics);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, r, m) {
                        eprintln!("Error handling connection: {e}");
                    }
                });
            }
            Err(e) => eprintln!("Accept error: {e}"),
        }
    }

    Ok(())
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn handle_connection(
    mut stream: TcpStream,
    reader: Arc<IpAtlasReader>,
    metrics: Arc<Metrics>,
) -> std::io::Result<()> {
    metrics.total_requests.fetch_add(1, Ordering::Relaxed);
    // Bounded read limit (8 KB) to prevent DoS via infinite unbounded headers
    let mut reader_buf = BufReader::new((&stream).take(8192));
    let mut request_line = String::new();
    if reader_buf.read_line(&mut request_line)? == 0 {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "GET" {
        metrics.errors.fetch_add(1, Ordering::Relaxed);
        let resp = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(resp.as_bytes())?;
        return Ok(());
    }

    let path = parts[1];

    if path == "/healthz" || path == "/health" {
        let body = "{\"status\":\"UP\"}\n";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes())?;
        return Ok(());
    }

    if path == "/metrics" {
        let total = metrics.total_requests.load(Ordering::Relaxed);
        let lookups = metrics.lookup_requests.load(Ordering::Relaxed);
        let threats = metrics.threats_detected.load(Ordering::Relaxed);
        let errors = metrics.errors.load(Ordering::Relaxed);

        let body = format!(
            "# HELP ipatlas_requests_total Total HTTP requests received\n\
             # TYPE ipatlas_requests_total counter\n\
             ipatlas_requests_total {}\n\
             # HELP ipatlas_lookups_total Total IP lookup evaluations\n\
             # TYPE ipatlas_lookups_total counter\n\
             ipatlas_lookups_total {}\n\
             # HELP ipatlas_threats_detected_total Total threat IPs detected\n\
             # TYPE ipatlas_threats_detected_total counter\n\
             ipatlas_threats_detected_total {}\n\
             # HELP ipatlas_errors_total Total HTTP error responses\n\
             # TYPE ipatlas_errors_total counter\n\
             ipatlas_errors_total {}\n",
            total, lookups, threats, errors
        );

        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes())?;
        return Ok(());
    }

    if let Some(ip_str) = path.strip_prefix("/lookup/") {
        metrics.lookup_requests.fetch_add(1, Ordering::Relaxed);
        let ip_clean = ip_str.split('?').next().unwrap_or(ip_str);
        let ip_parsed = match ip_clean.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                metrics.errors.fetch_add(1, Ordering::Relaxed);
                let body = "{\"error\":\"Invalid IP address\"}\n";
                let resp = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes())?;
                return Ok(());
            }
        };

        let t0 = Instant::now();
        let res = reader.lookup_ref(ip_parsed);
        let elapsed_ns = t0.elapsed().as_nanos();

        // Safely format parsed IP representation (prevents reflect-injection)
        let safe_ip = ip_parsed.to_string();

        let body = match res {
            Some(rec) => {
                let is_threat = rec.flags.is_threat();
                if is_threat {
                    metrics.threats_detected.fetch_add(1, Ordering::Relaxed);
                }
                format!(
                    "{{\"ip\":\"{}\",\"country\":\"{}\",\"region\":\"{}\",\"city\":\"{}\",\"isp\":\"{}\",\"asn\":{},\"lat\":{:.2},\"lon\":{:.2},\"threat\":{},\"datacenter\":{},\"lookup_ns\":{}}}\n",
                    safe_ip,
                    json_escape(rec.country),
                    json_escape(rec.region),
                    json_escape(rec.city),
                    json_escape(rec.isp),
                    rec.asn,
                    rec.latitude,
                    rec.longitude,
                    is_threat,
                    rec.flags.is_datacenter(),
                    elapsed_ns
                )
            }
            None => {
                format!(
                    "{{\"ip\":\"{}\",\"found\":false,\"lookup_ns\":{}}}\n",
                    safe_ip, elapsed_ns
                )
            }
        };

        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes())?;
        return Ok(());
    }

    metrics.errors.fetch_add(1, Ordering::Relaxed);
    let body = "{\"error\":\"Not Found\"}\n";
    let resp = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes())?;
    Ok(())
}
