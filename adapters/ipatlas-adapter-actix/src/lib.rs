//! Actix-web middleware for IPAtlas geolocation and threat detection.
//!
//! Attaches resolved [`ClientGeo`] to request extensions or short-circuits
//! malicious requests with `403 Forbidden`.

use std::future::{ready, Ready};
use std::net::IpAddr;
use std::sync::Arc;

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage, HttpResponse};
use futures_util::future::Either;
use ipatlas_core::{GeoFlags, GeoRecord, IpAtlasReader};

/// Resolved client geolocation metadata attached to Actix-web request extensions.
#[derive(Clone, Debug, PartialEq)]
pub struct ClientGeo {
    pub ip: IpAddr,
    pub country: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub asn: u32,
    pub latitude: f32,
    pub longitude: f32,
    pub flags: GeoFlags,
}

impl ClientGeo {
    pub fn new(ip: IpAddr, record: Option<GeoRecord>) -> Self {
        match record {
            Some(r) => Self {
                ip,
                country: r.country,
                region: r.region,
                city: r.city,
                isp: r.isp,
                asn: r.asn,
                latitude: r.latitude,
                longitude: r.longitude,
                flags: r.flags,
            },
            None => Self {
                ip,
                country: "--".into(),
                region: String::new(),
                city: String::new(),
                isp: String::new(),
                asn: 0,
                latitude: 0.0,
                longitude: 0.0,
                flags: GeoFlags(0),
            },
        }
    }

    pub fn is_threat(&self) -> bool {
        self.flags.is_threat()
    }
}

/// Actix-web Transform middleware factory.
#[derive(Clone)]
pub struct IpAtlasMiddleware {
    reader: Arc<IpAtlasReader>,
    strict_threat_block: bool,
    trust_forwarded_headers: bool,
}

impl IpAtlasMiddleware {
    pub fn new(reader: Arc<IpAtlasReader>) -> Self {
        Self {
            reader,
            strict_threat_block: false,
            trust_forwarded_headers: false,
        }
    }

    pub fn with_strict_threat_block(mut self, enabled: bool) -> Self {
        self.strict_threat_block = enabled;
        self
    }

    pub fn with_trusted_proxies(mut self, enabled: bool) -> Self {
        self.trust_forwarded_headers = enabled;
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for IpAtlasMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = IpAtlasMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(IpAtlasMiddlewareService {
            service,
            reader: Arc::clone(&self.reader),
            strict_threat_block: self.strict_threat_block,
            trust_forwarded_headers: self.trust_forwarded_headers,
        }))
    }
}

pub struct IpAtlasMiddlewareService<S> {
    service: S,
    reader: Arc<IpAtlasReader>,
    strict_threat_block: bool,
    trust_forwarded_headers: bool,
}

impl<S, B> Service<ServiceRequest> for IpAtlasMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = Either<
        Ready<Result<Self::Response, Self::Error>>,
        futures_util::future::Map<
            S::Future,
            fn(Result<ServiceResponse<B>, Error>) -> Result<Self::Response, Error>,
        >,
    >;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let client_ip = extract_ip(&req, self.trust_forwarded_headers);

        // 1. Fast zero-allocation threat lookup (~15-20 ns)
        let flags = self.reader.lookup_flags(client_ip).unwrap_or(GeoFlags(0));

        // 2. Strict threat blocking: reject before inner handler call
        if self.strict_threat_block && flags.is_threat() {
            let res = req
                .into_response(HttpResponse::Forbidden().finish())
                .map_into_right_body();
            return Either::Left(ready(Ok(res)));
        }

        // 3. Resolve metadata and inject into request extensions
        let geo = ClientGeo::new(client_ip, self.reader.lookup(client_ip));
        req.extensions_mut().insert(geo);

        use futures_util::FutureExt;
        Either::Right(
            self.service
                .call(req)
                .map(|res| res.map(|r| r.map_into_left_body())),
        )
    }
}

fn extract_ip(req: &ServiceRequest, trust_forwarded: bool) -> IpAddr {
    if trust_forwarded {
        if let Some(forwarded) = req.headers().get("x-forwarded-for") {
            if let Ok(s) = forwarded.to_str() {
                if let Some(first_ip) = s.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
    }

    if let Some(peer_addr) = req.peer_addr() {
        return peer_addr.ip();
    }

    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}
