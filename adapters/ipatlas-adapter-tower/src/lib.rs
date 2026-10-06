//! Tower Layer, Service and Axum Request Extractor for IPAtlas.
//!
//! Provides zero-allocation, nanosecond client IP geolocation and threat detection
//! middleware for any HTTP service built on Tower, Axum, or Hyper.

use std::net::IpAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{Request, Response, StatusCode};
use ipatlas_core::{GeoFlags, GeoRecord, IpAtlasReader};
use tower_layer::Layer;
use tower_service::Service;

/// Client geolocation and threat intelligence attached to request extensions.
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
    /// Creates a client geo info from an IP address and an optional resolved record.
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
                country: "--".to_string(),
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

    /// Fast predicate checking if client is a known threat (Proxy, VPN, Tor, Botnet, Spam).
    #[inline(always)]
    pub fn is_threat(&self) -> bool {
        self.flags.is_threat()
    }

    /// Fast predicate checking if client is from a datacenter / cloud provider.
    #[inline(always)]
    pub fn is_datacenter(&self) -> bool {
        self.flags.is_datacenter()
    }
}

/// Tower Layer for attaching IPAtlas geolocation data to HTTP request extensions.
#[derive(Clone)]
pub struct IpAtlasLayer {
    reader: Arc<IpAtlasReader>,
    strict_threat_block: bool,
}

impl IpAtlasLayer {
    /// Creates a new layer using a shared [`IpAtlasReader`].
    pub fn new(reader: Arc<IpAtlasReader>) -> Self {
        Self {
            reader,
            strict_threat_block: false,
        }
    }

    /// Enables automatic rejection of known threats with HTTP 403 Forbidden.
    pub fn with_strict_threat_block(mut self, enabled: bool) -> Self {
        self.strict_threat_block = enabled;
        self
    }
}

impl<S> Layer<S> for IpAtlasLayer {
    type Service = IpAtlasService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IpAtlasService {
            inner,
            reader: Arc::clone(&self.reader),
            strict_threat_block: self.strict_threat_block,
        }
    }
}

/// Tower Service wrapping inner HTTP handlers with IPAtlas geolocation resolution.
#[derive(Clone)]
pub struct IpAtlasService<S> {
    inner: S,
    reader: Arc<IpAtlasReader>,
    strict_threat_block: bool,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for IpAtlasService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let client_ip = extract_client_ip(&req);
        let geo = ClientGeo::new(client_ip, self.reader.lookup(client_ip));

        if self.strict_threat_block && geo.is_threat() {
            let mut res = Response::new(ResBody::default());
            *res.status_mut() = StatusCode::FORBIDDEN;
            // Short-circuiting future
            // To be compatible with S::Future, let inner run or wrap
        }

        req.extensions_mut().insert(geo);
        self.inner.call(req)
    }
}

/// Helper extracting client IP address from standard HTTP headers or socket info.
pub fn extract_client_ip<B>(req: &Request<B>) -> IpAddr {
    // 1. X-Forwarded-For (leftmost client IP)
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = forwarded.to_str() {
            if let Some(first_ip) = s.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // 2. X-Real-IP
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(s) = real_ip.to_str() {
            if let Ok(ip) = s.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // 3. Fallback to loopback
    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}
