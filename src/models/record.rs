use std::net::Ipv4Addr;

/// Bitmask representation of threat classifications and ISP usage types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GeoFlags(pub u16);

impl GeoFlags {
    pub const DATACENTER: u16 = 0x0001; // Datacenter / Web Hosting (VPN / Proxy / Bot origin)
    pub const RESIDENTIAL: u16 = 0x0002; // Fixed Residential ISP
    pub const MOBILE: u16 = 0x0004; // Mobile Carrier
    pub const COMMERCIAL: u16 = 0x0008; // Commercial Enterprise
    pub const ORGANIZATION: u16 = 0x0010; // Organization
    pub const GOVERNMENT: u16 = 0x0020; // Government / Military
    pub const EDUCATION: u16 = 0x0040; // University / School / Library
    pub const CDN: u16 = 0x0080; // Content Delivery Network
    pub const SPAM: u16 = 0x0100; // Spam Source
    pub const SCANNER: u16 = 0x0200; // Port / Vulnerability Scanner
    pub const BOTNET: u16 = 0x0400; // DDoS / Botnet Node
    pub const PROXY: u16 = 0x0800; // Proxy / VPN Anonymizer

    #[inline(always)]
    pub fn is_datacenter(&self) -> bool {
        (self.0 & Self::DATACENTER) != 0
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
    pub fn is_commercial(&self) -> bool {
        (self.0 & Self::COMMERCIAL) != 0
    }

    #[inline(always)]
    pub fn is_organization(&self) -> bool {
        (self.0 & Self::ORGANIZATION) != 0
    }

    #[inline(always)]
    pub fn is_government(&self) -> bool {
        (self.0 & Self::GOVERNMENT) != 0
    }

    #[inline(always)]
    pub fn is_education(&self) -> bool {
        (self.0 & Self::EDUCATION) != 0
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
        (self.0 & Self::PROXY) != 0
    }
}

/// Zero-copy borrowed view of a resolved IP lookup directly from mmap slices.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GeoRecordRef<'a> {
    pub ip: Ipv4Addr,
    pub ip_from: u32,
    pub ip_to: u32,
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
        format!(
            "{} - {}",
            Ipv4Addr::from(self.ip_from),
            Ipv4Addr::from(self.ip_to)
        )
    }

    pub fn to_owned(&self) -> GeoRecord {
        GeoRecord {
            ip: self.ip,
            ip_from: self.ip_from,
            ip_to: self.ip_to,
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
    pub ip: Ipv4Addr,
    pub ip_from: u32,
    pub ip_to: u32,
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
        format!(
            "{} - {}",
            Ipv4Addr::from(self.ip_from),
            Ipv4Addr::from(self.ip_to)
        )
    }
}
