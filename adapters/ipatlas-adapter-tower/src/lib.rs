//! Tower Layer, Service and Request Extension Extractor for IPAtlas.
//!
//! Provides client IP geolocation and threat detection middleware for HTTP services
//! built on Tower, Axum, or Hyper.

use std::future::{ready, Ready};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::Either;
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
    trust_forwarded_headers: bool,
}

impl IpAtlasLayer {
    /// Creates a new layer using a shared [`IpAtlasReader`].
    ///
    /// By default, `trust_forwarded_headers` is disabled for security: client IP
    /// is resolved from socket connection information. If running behind a trusted
    /// reverse proxy (Nginx, Cloudflare, Envoy), enable [`with_trusted_proxies`](Self::with_trusted_proxies).
    pub fn new(reader: Arc<IpAtlasReader>) -> Self {
        Self {
            reader,
            strict_threat_block: false,
            trust_forwarded_headers: false,
        }
    }

    /// Enables automatic rejection of known threats with `403 Forbidden` short-circuiting.
    pub fn with_strict_threat_block(mut self, enabled: bool) -> Self {
        self.strict_threat_block = enabled;
        self
    }

    /// Configures whether to inspect `X-Forwarded-For` and `X-Real-IP` HTTP headers.
    ///
    /// # Security Warning
    /// Only enable this option if your service is deployed behind a trusted reverse
    /// proxy that strips or sanitizes spoofed client headers. Enabling this on public-facing
    /// listeners allows untrusted clients to bypass threat filtering.
    pub fn with_trusted_proxies(mut self, trusted: bool) -> Self {
        self.trust_forwarded_headers = trusted;
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
            trust_forwarded_headers: self.trust_forwarded_headers,
        }
    }
}

/// Tower Service wrapping inner HTTP handlers with IPAtlas geolocation resolution.
#[derive(Clone)]
pub struct IpAtlasService<S> {
    inner: S,
    reader: Arc<IpAtlasReader>,
    strict_threat_block: bool,
    trust_forwarded_headers: bool,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for IpAtlasService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Either<Ready<Result<Self::Response, Self::Error>>, S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let client_ip = extract_client_ip(&req, self.trust_forwarded_headers);

        // 1. Fast zero-allocation threat check via bitflags (sub-20ns)
        let flags = self.reader.lookup_flags(client_ip).unwrap_or(GeoFlags(0));

        // 2. Short-circuit on threat if strict blocking is enabled
        if self.strict_threat_block && flags.is_threat() {
            let mut res = Response::new(ResBody::default());
            *res.status_mut() = StatusCode::FORBIDDEN;
            return Either::Left(ready(Ok(res)));
        }

        // 3. Resolve full metadata for downstream handlers
        let geo = ClientGeo::new(client_ip, self.reader.lookup(client_ip));
        req.extensions_mut().insert(geo);

        Either::Right(self.inner.call(req))
    }
}

/// Extracts client IP address from socket extensions or headers.
///
/// If `trust_forwarded` is true, parses `X-Forwarded-For` / `X-Real-IP`.
/// Otherwise, checks `SocketAddr` in request extensions (e.g. from Axum `ConnectInfo`),
/// falling back to loopback `127.0.0.1` if no connection info is found.
pub fn extract_client_ip<B>(req: &Request<B>, trust_forwarded: bool) -> IpAddr {
    // 1. Check socket address in extensions first (safe direct connection info)
    if let Some(&socket_addr) = req.extensions().get::<SocketAddr>() {
        if !trust_forwarded {
            return socket_addr.ip();
        }
    }

    // 2. If trusted, inspect standard proxy headers
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

        if let Some(real_ip) = req.headers().get("x-real-ip") {
            if let Ok(s) = real_ip.to_str() {
                if let Ok(ip) = s.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // 3. Check socket addr extension if headers were absent
    if let Some(&socket_addr) = req.extensions().get::<SocketAddr>() {
        return socket_addr.ip();
    }

    // 4. Safe fallback
    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}
