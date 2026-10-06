use std::sync::Arc;

use actix_web::test::TestRequest;
use actix_web::{test, web, App, HttpMessage, HttpResponse, Responder};
use ipatlas_adapter_actix::{ClientGeo, IpAtlasMiddleware};
use ipatlas_core::{compile, CompilerOptions, IpAtlasReader};
use tempfile::tempdir;

async fn test_handler(req: actix_web::HttpRequest) -> impl Responder {
    let geo = req.extensions().get::<ClientGeo>().cloned();
    match geo {
        Some(g) => HttpResponse::Ok().body(format!("Country: {}", g.country)),
        None => HttpResponse::InternalServerError().body("No geo metadata"),
    }
}

#[actix_web::test]
async fn test_actix_middleware_resolution_and_blocking() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("geo.csv");
    let px_path = dir.path().join("px.csv");
    let out_bin = dir.path().join("actix_test.bin");

    let clean_ip_u32 = 0x01020304u32;
    let threat_ip_u32 = 0x05060708u32;

    std::fs::write(
        &db_path,
        format!(
            "{clean_ip_u32},{clean_ip_u32},US,United States,CA,Los Angeles,34.05,-118.25\n\
             {threat_ip_u32},{threat_ip_u32},RU,Russia,MOW,Moscow,55.75,37.61\n"
        ),
    )
    .unwrap();

    std::fs::write(
        &px_path,
        format!("{threat_ip_u32},{threat_ip_u32},TOR,TorExitNode\n"),
    )
    .unwrap();

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db_path))
        .proxy(Some(&px_path));
    compile(opts).unwrap();

    let reader = Arc::new(IpAtlasReader::open(&out_bin).unwrap());

    // 1. App without threat block
    let app = test::init_service(
        App::new()
            .wrap(IpAtlasMiddleware::new(Arc::clone(&reader)))
            .route("/test", web::get().to(test_handler)),
    )
    .await;

    let req = TestRequest::get()
        .uri("/test")
        .peer_addr("1.2.3.4:12345".parse().unwrap())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // 2. App with strict threat blocking enabled
    let secure_app = test::init_service(
        App::new()
            .wrap(IpAtlasMiddleware::new(Arc::clone(&reader)).with_strict_threat_block(true))
            .route("/test", web::get().to(test_handler)),
    )
    .await;

    // Clean IP passes
    let req_clean = TestRequest::get()
        .uri("/test")
        .peer_addr("1.2.3.4:12345".parse().unwrap())
        .to_request();
    let resp_clean = test::call_service(&secure_app, req_clean).await;
    assert_eq!(resp_clean.status(), 200);

    // Threat IP (Tor) short-circuits with 403 Forbidden
    let req_threat = TestRequest::get()
        .uri("/test")
        .peer_addr("5.6.7.8:12345".parse().unwrap())
        .to_request();
    let resp_threat = test::call_service(&secure_app, req_threat).await;
    assert_eq!(resp_threat.status(), 403);
}
