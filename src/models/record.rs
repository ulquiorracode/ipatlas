use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Bitmask representation of threat classifications and ISP usage types (16-bit packed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GeoFlags(pub u16);

impl GeoFlags {
    // === 9 Official Proxy Types from IP2Proxy Specification ===
    pub const VPN: u16 = 1 << 0; // VPN Anonymizer
    pub const TOR: u16 = 1 << 1; // Tor Exit Node
    pub const DCH: u16 = 1 << 2; // Datacenter / Hosting / Cloud
    pub const PUB: u16 = 1 << 3; // Public HTTP/SOCKS Proxy
    pub const WEB: u16 = 1 << 4; // Web-based Proxy
    pub const SES: u16 = 1 << 5; // Search Engine Spider / Crawler
    pub const RES: u16 = 1 << 6; // Residential Proxy
    pub const CPN: u16 = 1 << 7; // Consumer Privacy Network (e.g. Apple Private Relay)
    pub const EPN: u16 = 1 << 8; // Enterprise Private Network

    // === Threat Intelligence & Usage Types ===
    pub const SPAM: u16 = 1 << 9; // Known Spam Source
    pub const SCANNER: u16 = 1 << 10; // Port / Vulnerability Scanner
    pub const BOTNET: u16 = 1 << 11; // DDoS / Botnet / Malware Node
    pub const MOBILE: u16 = 1 << 12; // Mobile Carrier / Cellular (MOB)
    pub const CDN: u16 = 1 << 13; // Content Delivery Network (CDN)
    pub const RESIDENTIAL: u16 = 1 << 14; // Fixed Residential ISP
    pub const ANY_PROXY: u16 = 1 << 15; // Generic Anonymizer / Proxy indicator

    // Backward-compatibility aliases
    pub const DATACENTER: u16 = Self::DCH;
    pub const PROXY: u16 = Self::ANY_PROXY;

    #[inline(always)]
    pub fn is_vpn(&self) -> bool {
        (self.0 & Self::VPN) != 0
    }

    #[inline(always)]
    pub fn is_tor(&self) -> bool {
        (self.0 & Self::TOR) != 0
    }

    #[inline(always)]
    pub fn is_datacenter(&self) -> bool {
        (self.0 & Self::DCH) != 0
    }

    #[inline(always)]
    pub fn is_public_proxy(&self) -> bool {
        (self.0 & Self::PUB) != 0
    }

    #[inline(always)]
    pub fn is_pub(&self) -> bool {
        self.is_public_proxy()
    }

    #[inline(always)]
    pub fn is_web_proxy(&self) -> bool {
        (self.0 & Self::WEB) != 0
    }

    #[inline(always)]
    pub fn is_web(&self) -> bool {
        self.is_web_proxy()
    }

    #[inline(always)]
    pub fn is_search_spider(&self) -> bool {
        (self.0 & Self::SES) != 0
    }

    #[inline(always)]
    pub fn is_ses(&self) -> bool {
        self.is_search_spider()
    }

    #[inline(always)]
    pub fn is_residential_proxy(&self) -> bool {
        (self.0 & Self::RES) != 0
    }

    #[inline(always)]
    pub fn is_res(&self) -> bool {
        self.is_residential_proxy()
    }

    #[inline(always)]
    pub fn is_consumer_privacy_network(&self) -> bool {
        (self.0 & Self::CPN) != 0
    }

    #[inline(always)]
    pub fn is_cpn(&self) -> bool {
        self.is_consumer_privacy_network()
    }

    #[inline(always)]
    pub fn is_enterprise_private_network(&self) -> bool {
        (self.0 & Self::EPN) != 0
    }

    #[inline(always)]
    pub fn is_epn(&self) -> bool {
        self.is_enterprise_private_network()
    }

    #[inline(always)]
    pub fn is_residential(&self) -> bool {
        (self.0 & Self::RESIDENTIAL) != 0
    }

    #[inline(always)]
    pub fn is_mobile(&self) -> bool {
        (self.0 & Self::MOBILE) != 0
    }

    #[inline(always)]
    pub fn is_cdn(&self) -> bool {
        (self.0 & Self::CDN) != 0
    }

    #[inline(always)]
    pub fn is_spam(&self) -> bool {
        (self.0 & Self::SPAM) != 0
    }

    #[inline(always)]
    pub fn is_scanner(&self) -> bool {
        (self.0 & Self::SCANNER) != 0
    }

    #[inline(always)]
    pub fn is_botnet(&self) -> bool {
        (self.0 & Self::BOTNET) != 0
    }

    #[inline(always)]
    pub fn is_proxy(&self) -> bool {
        (self.0
            & (Self::ANY_PROXY
                | Self::VPN
                | Self::TOR
                | Self::PUB
                | Self::WEB
                | Self::RES
                | Self::CPN
                | Self::EPN))
            != 0
    }
}

/// Zero-copy borrowed view of a resolved IP lookup directly from mmap slices.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GeoRecordRef<'a> {
    pub ip: IpAddr,
    pub ip_from: u128,
    pub ip_to: u128,
    pub is_v6: bool,
    pub country: &'a str,
    pub region: &'a str,
    pub city: &'a str,
    pub isp: &'a str,
    pub asn: u32,
    pub latitude: f32,
    pub longitude: f32,
    pub flags: GeoFlags,
}

impl<'a> GeoRecordRef<'a> {
    pub fn range_str(&self) -> String {
        if self.is_v6 {
            format!(
                "{} - {}",
                Ipv6Addr::from(self.ip_from),
                Ipv6Addr::from(self.ip_to)
            )
        } else {
            format!(
                "{} - {}",
                Ipv4Addr::from(self.ip_from as u32),
                Ipv4Addr::from(self.ip_to as u32)
            )
        }
    }

    pub fn to_owned(&self) -> GeoRecord {
        GeoRecord {
            ip: self.ip,
            ip_from: self.ip_from,
            ip_to: self.ip_to,
            is_v6: self.is_v6,
            country: self.country.to_string(),
            region: self.region.to_string(),
            city: self.city.to_string(),
            isp: self.isp.to_string(),
            asn: self.asn,
            latitude: self.latitude,
            longitude: self.longitude,
            flags: self.flags,
        }
    }
}

/// Owned GeoIP & Threat record with allocated strings.
#[derive(Clone, Debug, PartialEq)]
pub struct GeoRecord {
    pub ip: IpAddr,
    pub ip_from: u128,
    pub ip_to: u128,
    pub is_v6: bool,
    pub country: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub asn: u32,
    pub latitude: f32,
    pub longitude: f32,
    pub flags: GeoFlags,
}

impl GeoRecord {
    pub fn range_str(&self) -> String {
        if self.is_v6 {
            format!(
                "{} - {}",
                Ipv6Addr::from(self.ip_from),
                Ipv6Addr::from(self.ip_to)
            )
        } else {
            format!(
                "{} - {}",
                Ipv4Addr::from(self.ip_from as u32),
                Ipv4Addr::from(self.ip_to as u32)
            )
        }
    }
}
