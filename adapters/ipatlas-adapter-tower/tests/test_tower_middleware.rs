use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::Extension;
use axum::http::Request;
use axum::routing::get;
use axum::Router;
use ipatlas_adapter_tower::{extract_client_ip, ClientGeo, IpAtlasLayer};
use ipatlas_core::{compile, CompilerOptions, IpAtlasReader};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn test_tower_middleware_extension_and_resolution() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("geo.csv");
    let px_path = dir.path().join("px.csv");
    let out_bin = dir.path().join("test.bin");

    // Sample IP: 1.2.3.4 (US, Los Angeles, Datacenter)
    let ip_u32 = 0x01020304u32;
    std::fs::write(
        &db_path,
        format!("{ip_u32},{ip_u32},US,United States,CA,Los Angeles,34.05,-118.25\n"),
    )
    .unwrap();
    std::fs::write(&px_path, format!("{ip_u32},{ip_u32},DCH,CloudISP\n")).unwrap();

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db_path))
        .proxy(Some(&px_path));
    compile(opts).unwrap();

    let reader = Arc::new(IpAtlasReader::open(&out_bin).unwrap());

    // Build Axum app with IpAtlasLayer configured for trusted proxies
    let app = Router::new()
        .route(
            "/test",
            get(|Extension(geo): Extension<ClientGeo>| async move {
                assert_eq!(geo.country, "US");
                assert_eq!(geo.city, "Los Angeles");
                assert!(geo.is_datacenter());
                "OK"
            }),
        )
        .layer(IpAtlasLayer::new(reader).with_trusted_proxies(true));

    // Request with X-Forwarded-For header
    let req = Request::builder()
        .uri("/test")
        .header("x-forwarded-for", "1.2.3.4, 10.0.0.1")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_tower_strict_threat_block_short_circuits() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("geo.csv");
    let px_path = dir.path().join("px.csv");
    let out_bin = dir.path().join("test_block.bin");

    // Threat IP: 5.5.5.5 (Tor / Botnet)
    let threat_ip_u32 = 0x05050505u32;
    std::fs::write(
        &db_path,
        format!("{threat_ip_u32},{threat_ip_u32},RU,Russia,MOW,Moscow,55.75,37.61\n"),
    )
    .unwrap();
    std::fs::write(
        &px_path,
        format!("{threat_ip_u32},{threat_ip_u32},TOR,TorISP\n"),
    )
    .unwrap();

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db_path))
        .proxy(Some(&px_path));
    compile(opts).unwrap();

    let reader = Arc::new(IpAtlasReader::open(&out_bin).unwrap());
    let handler_executed = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&handler_executed);

    let app = Router::new()
        .route(
            "/protected",
            get(move || {
                let executed = Arc::clone(&handler_flag);
                async move {
                    executed.store(true, Ordering::SeqCst);
                    "Should never reach here"
                }
            }),
        )
        .layer(
            IpAtlasLayer::new(reader)
                .with_strict_threat_block(true)
                .with_trusted_proxies(true),
        );

    let req = Request::builder()
        .uri("/protected")
        .header("x-forwarded-for", "5.5.5.5")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    // 1. Must return 403 Forbidden
    assert_eq!(response.status(), 403);
    // 2. Inner handler MUST NOT have executed
    assert!(!handler_executed.load(Ordering::SeqCst));
}

#[test]
fn test_client_ip_extraction_security() {
    // 1. Untrusted proxy: ignores spoofed X-Forwarded-For, uses socket addr
    let mut req1 = Request::builder()
        .header("x-forwarded-for", "8.8.8.8, 1.1.1.1")
        .header("x-real-ip", "9.9.9.9")
        .body(())
        .unwrap();
    let real_socket: SocketAddr = "192.168.1.50:8080".parse().unwrap();
    req1.extensions_mut().insert(real_socket);

    assert_eq!(
        extract_client_ip(&req1, false),
        "192.168.1.50".parse::<IpAddr>().unwrap()
    );

    // 2. Trusted proxy: honors X-Forwarded-For
    assert_eq!(
        extract_client_ip(&req1, true),
        "8.8.8.8".parse::<IpAddr>().unwrap()
    );

    // 3. Fallback to loopback
    let req2 = Request::builder().body(()).unwrap();
    assert_eq!(
        extract_client_ip(&req2, false),
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
}
