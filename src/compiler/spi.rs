//! Pluggable Service Provider Interface (SPI) for IP dataset ingestion.
//!
//! Decouples core sweep-line compilation and storage from specific third-party
//! dataset schemas (IP2Location, MaxMind GeoLite2, DB-IP, custom threat feeds).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::compiler::parser::{RawGeoRecord, RawGeoRecordV6, RawPxRecord, RawPxRecordV6};
use crate::compiler::writer::StringPool;

/// Normalized intermediate interval record for custom feed ingestion (IPv4).
#[derive(Clone, Debug, PartialEq)]
pub struct IngestRecordV4 {
    pub ip_from: u32,
    pub ip_to: u32,
    pub country: [u8; 2],
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub asn: u32,
    pub latitude: f32,
    pub longitude: f32,
    pub flags: u16,
}

impl IngestRecordV4 {
    /// Constructs an ingest record from a CIDR block.
    pub fn from_cidr(cidr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR format: {cidr}"));
        }
        let ip: Ipv4Addr = parts[0].parse().map_err(|e| format!("{e}"))?;
        let prefix_len: u32 = parts[1].parse().map_err(|e| format!("{e}"))?;
        if prefix_len > 32 {
            return Err(format!("Invalid IPv4 prefix length: {prefix_len}"));
        }
        let ip_num = u32::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let ip_from = ip_num & mask;
        let ip_to = ip_from | !mask;

        Ok(Self {
            ip_from,
            ip_to,
            country: *b"--",
            region: None,
            city: None,
            isp: None,
            asn: 0,
            latitude: 0.0,
            longitude: 0.0,
            flags: 0,
        })
    }

    /// Converts this record into compiler-ready internal representations.
    pub fn into_raw_pair(
        self,
        cities: &mut StringPool,
        regions: &mut StringPool,
        isps: &mut StringPool,
        prune_empty: bool,
    ) -> (RawGeoRecord, RawPxRecord) {
        let city_idx = self
            .city
            .as_deref()
            .map(|c| cities.get_or_insert(c, prune_empty))
            .unwrap_or(0);
        let reg_idx = self
            .region
            .as_deref()
            .map(|r| {
                let raw = regions.get_or_insert(r, prune_empty);
                if raw <= u16::MAX as u32 {
                    raw as u16
                } else {
                    0
                }
            })
            .unwrap_or(0);
        let isp_idx = self
            .isp
            .as_deref()
            .map(|i| {
                let raw = isps.get_or_insert(i, prune_empty);
                if raw <= u16::MAX as u32 {
                    raw as u16
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let lat_fixed = (self.latitude * 100.0)
            .round()
            .clamp(i16::MIN as f32, i16::MAX as f32) as i16;
        let lon_fixed = (self.longitude * 100.0)
            .round()
            .clamp(i16::MIN as f32, i16::MAX as f32) as i16;

        let geo = RawGeoRecord {
            ip_from: self.ip_from,
            ip_to: self.ip_to,
            city_idx,
            reg_idx,
            country: self.country,
            lat_fixed,
            lon_fixed,
        };

        let px = RawPxRecord {
            ip_from: self.ip_from,
            ip_to: self.ip_to,
            isp_idx,
            asn: self.asn,
            flags: self.flags,
        };

        (geo, px)
    }
}

/// Normalized intermediate interval record for custom feed ingestion (IPv6).
#[derive(Clone, Debug, PartialEq)]
pub struct IngestRecordV6 {
    pub ip_from: u128,
    pub ip_to: u128,
    pub country: [u8; 2],
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub asn: u32,
    pub latitude: f32,
    pub longitude: f32,
    pub flags: u16,
}

impl IngestRecordV6 {
    /// Constructs an IPv6 ingest record from a CIDR block.
    pub fn from_cidr(cidr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR format: {cidr}"));
        }
        let ip: Ipv6Addr = parts[0].parse().map_err(|e| format!("{e}"))?;
        let prefix_len: u32 = parts[1].parse().map_err(|e| format!("{e}"))?;
        if prefix_len > 128 {
            return Err(format!("Invalid IPv6 prefix length: {prefix_len}"));
        }
        let ip_num = u128::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !((1u128 << (128 - prefix_len)) - 1)
        };
        let ip_from = ip_num & mask;
        let ip_to = ip_from | !mask;

        Ok(Self {
            ip_from,
            ip_to,
            country: *b"--",
            region: None,
            city: None,
            isp: None,
            asn: 0,
            latitude: 0.0,
            longitude: 0.0,
            flags: 0,
        })
    }

    /// Converts this record into compiler-ready internal representations.
    pub fn into_raw_pair(
        self,
        cities: &mut StringPool,
        regions: &mut StringPool,
        isps: &mut StringPool,
        prune_empty: bool,
    ) -> (RawGeoRecordV6, RawPxRecordV6) {
        let city_idx = self
            .city
            .as_deref()
            .map(|c| cities.get_or_insert(c, prune_empty))
            .unwrap_or(0);
        let reg_idx = self
            .region
            .as_deref()
            .map(|r| {
                let raw = regions.get_or_insert(r, prune_empty);
                if raw <= u16::MAX as u32 {
                    raw as u16
                } else {
                    0
                }
            })
            .unwrap_or(0);
        let isp_idx = self
            .isp
            .as_deref()
            .map(|i| {
                let raw = isps.get_or_insert(i, prune_empty);
                if raw <= u16::MAX as u32 {
                    raw as u16
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let lat_fixed = (self.latitude * 100.0)
            .round()
            .clamp(i16::MIN as f32, i16::MAX as f32) as i16;
        let lon_fixed = (self.longitude * 100.0)
            .round()
            .clamp(i16::MIN as f32, i16::MAX as f32) as i16;

        let geo = RawGeoRecordV6 {
            ip_from: self.ip_from,
            ip_to: self.ip_to,
            city_idx,
            reg_idx,
            country: self.country,
            lat_fixed,
            lon_fixed,
        };

        let px = RawPxRecordV6 {
            ip_from: self.ip_from,
            ip_to: self.ip_to,
            isp_idx,
            asn: self.asn,
            flags: self.flags,
        };

        (geo, px)
    }
}

/// Service Provider Interface (SPI) trait for custom data source ingestion.
pub trait DatasetIngestionAdapter {
    /// Ingests records from an arbitrary data stream or file into the compiler collections.
    fn parse_v4(&mut self) -> Box<dyn Iterator<Item = IngestRecordV4> + '_>;
}
