use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::models::{FeatureMask, GeoFlags};

/// Raw parsed record from an IP2Location GeoIP CSV dataset (IPv4).
#[derive(Clone, Debug, PartialEq)]
pub struct RawGeoRecord {
    pub ip_from: u32,
    pub ip_to: u32,
    pub country: [u8; 2],
    pub region: String,
    pub city: String,
    pub lat_fixed: i16,
    pub lon_fixed: i16,
}

/// Raw parsed record from an IP2Location GeoIP CSV dataset (IPv6).
#[derive(Clone, Debug, PartialEq)]
pub struct RawGeoRecordV6 {
    pub ip_from: u128,
    pub ip_to: u128,
    pub country: [u8; 2],
    pub region: String,
    pub city: String,
    pub lat_fixed: i16,
    pub lon_fixed: i16,
}

/// Raw parsed record from an IP2Proxy Threat CSV dataset (IPv4).
#[derive(Clone, Debug, PartialEq)]
pub struct RawPxRecord {
    pub ip_from: u32,
    pub ip_to: u32,
    pub isp: String,
    pub asn: u32,
    pub flags: u16,
}

/// Raw parsed record from an IP2Proxy Threat CSV dataset (IPv6).
#[derive(Clone, Debug, PartialEq)]
pub struct RawPxRecordV6 {
    pub ip_from: u128,
    pub ip_to: u128,
    pub isp: String,
    pub asn: u32,
    pub flags: u16,
}

pub fn parse_px_flags(proxy_type: &str, usage_str: &str, threat_str: &str) -> u16 {
    let mut flags = 0u16;

    // 1. All 9 IP2Proxy official proxy types (PX2 - PX12)
    match proxy_type.trim() {
        "VPN" => flags |= GeoFlags::VPN | GeoFlags::ANY_PROXY,
        "TOR" => flags |= GeoFlags::TOR | GeoFlags::ANY_PROXY,
        "DCH" => flags |= GeoFlags::DCH,
        "PUB" => flags |= GeoFlags::PUB | GeoFlags::ANY_PROXY,
        "WEB" => flags |= GeoFlags::WEB | GeoFlags::ANY_PROXY,
        "SES" => flags |= GeoFlags::SES,
        "RES" => flags |= GeoFlags::RES | GeoFlags::ANY_PROXY,
        "CPN" => flags |= GeoFlags::CPN | GeoFlags::ANY_PROXY,
        "EPN" => flags |= GeoFlags::EPN | GeoFlags::ANY_PROXY,
        _ => {
            if !proxy_type.is_empty() && proxy_type != "-" {
                flags |= GeoFlags::ANY_PROXY;
            }
        }
    }

    // 2. Usage classification (DCH, MOB, CDN, ISP, SES, RES, etc.)
    if !usage_str.is_empty() {
        for u in usage_str.split('/') {
            let u_trim = u.trim();
            match u_trim {
                "DCH" => flags |= GeoFlags::DCH,
                "ISP" => flags |= GeoFlags::RESIDENTIAL,
                "MOB" => flags |= GeoFlags::MOBILE,
                "CDN" => flags |= GeoFlags::CDN,
                "SES" => flags |= GeoFlags::SES,
                "RES" => flags |= GeoFlags::RES | GeoFlags::ANY_PROXY,
                "VPN" => flags |= GeoFlags::VPN | GeoFlags::ANY_PROXY,
                "TOR" => flags |= GeoFlags::TOR | GeoFlags::ANY_PROXY,
                "PUB" => flags |= GeoFlags::PUB | GeoFlags::ANY_PROXY,
                "WEB" => flags |= GeoFlags::WEB | GeoFlags::ANY_PROXY,
                "CPN" => flags |= GeoFlags::CPN | GeoFlags::ANY_PROXY,
                "EPN" => flags |= GeoFlags::EPN | GeoFlags::ANY_PROXY,
                _ => {}
            }
        }
    }

    // 3. Security threat types
    if !threat_str.is_empty() {
        if threat_str.contains("SPAM") {
            flags |= GeoFlags::SPAM;
        }
        if threat_str.contains("SCANNER") {
            flags |= GeoFlags::SCANNER;
        }
        if threat_str.contains("BOTNET") {
            flags |= GeoFlags::BOTNET;
        }
    }

    flags
}

pub fn safe_parse_latlon(val: &str) -> i16 {
    let trimmed = val.trim().trim_matches('"');
    if let Ok(f) = trimmed.parse::<f64>() {
        let rounded = (f * 100.0).round();
        if rounded >= i16::MIN as f64 && rounded <= i16::MAX as f64 {
            return rounded as i16;
        }
    }
    0
}

pub fn safe_parse_asn(val: &str) -> u32 {
    let trimmed = val.trim().trim_matches('"');
    let s = if trimmed.starts_with("AS") || trimmed.starts_with("as") {
        &trimmed[2..]
    } else {
        trimmed
    };
    s.parse::<u32>().unwrap_or(0)
}

/// Parses a CSV row splitting by comma, respecting quotes.
pub fn parse_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::with_capacity(16);
    let bytes = line.as_bytes();
    let mut start = 0;
    let mut in_quotes = false;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                in_quotes = !in_quotes;
            }
            b',' if !in_quotes => {
                let slice = line[start..i].trim();
                let unquoted = slice
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(slice);
                fields.push(unquoted);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }

    if start <= bytes.len() {
        let slice = line[start..].trim();
        let unquoted = slice
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(slice);
        fields.push(unquoted);
    }

    fields
}

/// Reads IP2Location CSV lines as a streaming iterator.
pub fn stream_geo_file<P: AsRef<Path>>(
    path: P,
    features: FeatureMask,
) -> Result<impl Iterator<Item = RawGeoRecord>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(256 * 1024, file);

    let has_country = features.has_country();
    let has_region = features.has_region();
    let has_city = features.has_city();
    let has_coords = features.has_coords();

    Ok(reader.lines().filter_map(move |line_res| {
        let line = line_res.ok()?;
        if line.is_empty() {
            return None;
        }
        let fields = parse_csv_line(&line);
        if fields.len() < 2 {
            return None;
        }

        let ip_from = fields[0].parse::<u32>().ok()?;
        let ip_to = fields[1].parse::<u32>().ok()?;

        let mut country = *b"--";
        if has_country && fields.len() > 2 {
            let cc = fields[2].as_bytes();
            if cc.len() >= 2 {
                country = [cc[0], cc[1]];
            }
        }

        let region = if has_region && fields.len() > 4 {
            fields[4].to_string()
        } else {
            String::new()
        };

        let city = if has_city && fields.len() > 5 {
            fields[5].to_string()
        } else {
            String::new()
        };

        let (lat_fixed, lon_fixed) = if has_coords && fields.len() > 7 {
            (safe_parse_latlon(fields[6]), safe_parse_latlon(fields[7]))
        } else {
            (0, 0)
        };

        Some(RawGeoRecord {
            ip_from,
            ip_to,
            country,
            region,
            city,
            lat_fixed,
            lon_fixed,
        })
    }))
}

/// Reads IP2Proxy CSV lines as a streaming iterator.
pub fn stream_px_file<P: AsRef<Path>>(
    path: P,
    features: FeatureMask,
) -> Result<impl Iterator<Item = RawPxRecord>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(256 * 1024, file);

    let has_isp = features.has_isp();
    let has_asn = features.has_asn();
    let has_threats = features.has_threats();

    Ok(reader.lines().filter_map(move |line_res| {
        let line = line_res.ok()?;
        if line.is_empty() {
            return None;
        }
        let fields = parse_csv_line(&line);
        if fields.len() < 2 {
            return None;
        }

        let ip_from = fields[0].parse::<u32>().ok()?;
        let ip_to = fields[1].parse::<u32>().ok()?;

        let isp = if has_isp && fields.len() > 7 {
            fields[7].to_string()
        } else {
            String::new()
        };

        let asn = if has_asn && fields.len() > 10 {
            safe_parse_asn(fields[10])
        } else {
            0
        };

        let flags = if has_threats {
            let ptype = if fields.len() > 2 { fields[2] } else { "" };
            let usage = if fields.len() > 9 { fields[9] } else { "" };
            let threat = if fields.len() > 13 {
                fields[13]
            } else if fields.len() > 8 {
                fields
                    .iter()
                    .copied()
                    .find(|&s| s.contains("SPAM") || s.contains("SCANNER") || s.contains("BOTNET"))
                    .unwrap_or("")
            } else {
                ""
            };
            parse_px_flags(ptype, usage, threat)
        } else {
            0
        };

        Some(RawPxRecord {
            ip_from,
            ip_to,
            isp,
            asn,
            flags,
        })
    }))
}

/// Reads IP2Location IPv6 CSV lines as a streaming iterator.
pub fn stream_geo_file_v6<P: AsRef<Path>>(
    path: P,
    features: FeatureMask,
) -> Result<impl Iterator<Item = RawGeoRecordV6>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(256 * 1024, file);

    let has_country = features.has_country();
    let has_region = features.has_region();
    let has_city = features.has_city();
    let has_coords = features.has_coords();

    Ok(reader.lines().filter_map(move |line_res| {
        let line = line_res.ok()?;
        if line.is_empty() {
            return None;
        }
        let fields = parse_csv_line(&line);
        if fields.len() < 2 {
            return None;
        }

        let ip_from = fields[0].parse::<u128>().ok()?;
        let ip_to = fields[1].parse::<u128>().ok()?;

        let mut country = *b"--";
        if has_country && fields.len() > 2 {
            let cc = fields[2].as_bytes();
            if cc.len() >= 2 {
                country = [cc[0], cc[1]];
            }
        }

        let region = if has_region && fields.len() > 4 {
            fields[4].to_string()
        } else {
            String::new()
        };

        let city = if has_city && fields.len() > 5 {
            fields[5].to_string()
        } else {
            String::new()
        };

        let (lat_fixed, lon_fixed) = if has_coords && fields.len() > 7 {
            (safe_parse_latlon(fields[6]), safe_parse_latlon(fields[7]))
        } else {
            (0, 0)
        };

        Some(RawGeoRecordV6 {
            ip_from,
            ip_to,
            country,
            region,
            city,
            lat_fixed,
            lon_fixed,
        })
    }))
}

/// Reads IP2Proxy IPv6 CSV lines as a streaming iterator.
pub fn stream_px_file_v6<P: AsRef<Path>>(
    path: P,
    features: FeatureMask,
) -> Result<impl Iterator<Item = RawPxRecordV6>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(256 * 1024, file);

    let has_isp = features.has_isp();
    let has_asn = features.has_asn();
    let has_threats = features.has_threats();

    Ok(reader.lines().filter_map(move |line_res| {
        let line = line_res.ok()?;
        if line.is_empty() {
            return None;
        }
        let fields = parse_csv_line(&line);
        if fields.len() < 2 {
            return None;
        }

        let ip_from = fields[0].parse::<u128>().ok()?;
        let ip_to = fields[1].parse::<u128>().ok()?;

        let isp = if has_isp && fields.len() > 7 {
            fields[7].to_string()
        } else {
            String::new()
        };

        let asn = if has_asn && fields.len() > 10 {
            safe_parse_asn(fields[10])
        } else {
            0
        };

        let flags = if has_threats {
            let ptype = if fields.len() > 2 { fields[2] } else { "" };
            let usage = if fields.len() > 9 { fields[9] } else { "" };
            let threat = if fields.len() > 13 {
                fields[13]
            } else if fields.len() > 8 {
                fields
                    .iter()
                    .copied()
                    .find(|&s| s.contains("SPAM") || s.contains("SCANNER") || s.contains("BOTNET"))
                    .unwrap_or("")
            } else {
                ""
            };
            parse_px_flags(ptype, usage, threat)
        } else {
            0
        };

        Some(RawPxRecordV6 {
            ip_from,
            ip_to,
            isp,
            asn,
            flags,
        })
    }))
}
