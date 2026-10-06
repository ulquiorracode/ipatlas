use std::net::IpAddr;
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

    // Sample IP: 1.2.3.4 (US, Los Angeles, Datacenter + Proxy)
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

    // Build Axum app with IpAtlasLayer
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
        .layer(IpAtlasLayer::new(reader));

    // Request with X-Forwarded-For header
    let req = Request::builder()
        .uri("/test")
        .header("x-forwarded-for", "1.2.3.4, 10.0.0.1")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), 200);
}

#[test]
fn test_client_ip_extraction_precedence() {
    let req1 = Request::builder()
        .header("x-forwarded-for", "8.8.8.8, 1.1.1.1")
        .header("x-real-ip", "9.9.9.9")
        .body(())
        .unwrap();
    assert_eq!(
        extract_client_ip(&req1),
        "8.8.8.8".parse::<IpAddr>().unwrap()
    );

    let req2 = Request::builder()
        .header("x-real-ip", "9.9.9.9")
        .body(())
        .unwrap();
    assert_eq!(
        extract_client_ip(&req2),
        "9.9.9.9".parse::<IpAddr>().unwrap()
    );

    let req3 = Request::builder().body(()).unwrap();
    assert_eq!(
        extract_client_ip(&req3),
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
}
