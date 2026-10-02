use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::compiler::writer::StringPool;
use crate::models::{FeatureMask, GeoFlags};

/// Raw parsed record from an IP2Location CSV dataset (IPv4).
/// Completely stack-allocated, Copy, 20 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawGeoRecord {
    pub ip_from: u32,
    pub ip_to: u32,
    pub city_idx: u32,
    pub reg_idx: u16,
    pub country: [u8; 2],
    pub lat_fixed: i16,
    pub lon_fixed: i16,
}

/// Raw parsed record from an IP2Proxy Threat CSV dataset (IPv4).
/// Completely stack-allocated, Copy, 16 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawPxRecord {
    pub ip_from: u32,
    pub ip_to: u32,
    pub isp_idx: u16,
    pub asn: u32,
    pub flags: u16,
}

/// Raw parsed record from an IP2Location CSV dataset (IPv6).
/// Completely stack-allocated, Copy, 44 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawGeoRecordV6 {
    pub ip_from: u128,
    pub ip_to: u128,
    pub city_idx: u32,
    pub reg_idx: u16,
    pub country: [u8; 2],
    pub lat_fixed: i16,
    pub lon_fixed: i16,
}

/// Raw parsed record from an IP2Proxy Threat CSV dataset (IPv6).
/// Completely stack-allocated, Copy, 40 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawPxRecordV6 {
    pub ip_from: u128,
    pub ip_to: u128,
    pub isp_idx: u16,
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

#[inline]
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

#[inline]
pub fn safe_parse_asn(val: &str) -> u32 {
    let trimmed = val.trim().trim_matches('"');
    let s = if trimmed.starts_with("AS") || trimmed.starts_with("as") {
        &trimmed[2..]
    } else {
        trimmed
    };
    s.parse::<u32>().unwrap_or(0)
}

/// Zero-heap-allocation CSV row splitter operating on a fixed stack-allocated slice buffer.
#[inline(always)]
pub fn parse_csv_row_fixed<'a, const N: usize>(line: &'a str, out: &mut [&'a str; N]) -> usize {
    let bytes = line.as_bytes();
    let mut start = 0;
    let mut in_quotes = false;
    let mut i = 0;
    let mut count = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                if count < N {
                    let slice = line[start..i].trim();
                    let unquoted = slice
                        .strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .unwrap_or(slice);
                    out[count] = unquoted;
                    count += 1;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }

    if start <= bytes.len() && count < N {
        let slice = line[start..].trim();
        let unquoted = slice
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(slice);
        out[count] = unquoted;
        count += 1;
    }

    count
}

/// High-throughput zero-allocation GeoIP CSV streaming iterator (IPv4).
pub struct GeoRecordIter<'a, R> {
    reader: R,
    line_buf: String,
    has_country: bool,
    has_region: bool,
    has_city: bool,
    has_coords: bool,
    cities: &'a mut StringPool,
    regions: &'a mut StringPool,
    prune_empty: bool,
}

impl<'a, R: BufRead> Iterator for GeoRecordIter<'a, R> {
    type Item = RawGeoRecord;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line_buf.clear();
            let bytes_read = self.reader.read_line(&mut self.line_buf).ok()?;
            if bytes_read == 0 {
                return None;
            }
            let line = self.line_buf.trim();
            if line.is_empty() {
                continue;
            }

            let mut fields = [""; 16];
            let count = parse_csv_row_fixed(line, &mut fields);
            if count < 2 {
                continue;
            }

            let ip_from = match fields[0].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ip_to = match fields[1].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let mut country = *b"--";
            if self.has_country && count > 2 {
                let cc = fields[2].as_bytes();
                if cc.len() >= 2 {
                    country = [cc[0], cc[1]];
                }
            }

            let reg_idx = if self.has_region && count > 4 {
                let raw = self.regions.get_or_insert(fields[4], self.prune_empty);
                if raw <= u16::MAX as u32 {
                    raw as u16
                } else {
                    0
                }
            } else {
                0
            };

            let city_idx = if self.has_city && count > 5 {
                self.cities.get_or_insert(fields[5], self.prune_empty)
            } else {
                0
            };

            let (lat_fixed, lon_fixed) = if self.has_coords && count > 7 {
                (safe_parse_latlon(fields[6]), safe_parse_latlon(fields[7]))
            } else {
                (0, 0)
            };

            return Some(RawGeoRecord {
                ip_from,
                ip_to,
                city_idx,
                reg_idx,
                country,
                lat_fixed,
                lon_fixed,
            });
        }
    }
}

/// High-throughput zero-allocation Proxy/Threat CSV streaming iterator (IPv4).
pub struct PxRecordIter<'a, R> {
    reader: R,
    line_buf: String,
    has_isp: bool,
    has_asn: bool,
    has_threats: bool,
    isps: &'a mut StringPool,
    prune_empty: bool,
}

impl<'a, R: BufRead> Iterator for PxRecordIter<'a, R> {
    type Item = RawPxRecord;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line_buf.clear();
            let bytes_read = self.reader.read_line(&mut self.line_buf).ok()?;
            if bytes_read == 0 {
                return None;
            }
            let line = self.line_buf.trim();
            if line.is_empty() {
                continue;
            }

            let mut fields = [""; 16];
            let count = parse_csv_row_fixed(line, &mut fields);
            if count < 2 {
                continue;
            }

            let ip_from = match fields[0].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ip_to = match fields[1].parse::<u32>() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let isp_idx = if self.has_isp && count > 7 {
                let raw = self.isps.get_or_insert(fields[7], self.prune_empty);
                if raw <= u16::MAX as u32 {
                    raw as u16
                } else {
                    0
                }
            } else {
                0
            };

            let asn = if self.has_asn && count > 10 {
                safe_parse_asn(fields[10])
            } else {
                0
            };

            let flags = if self.has_threats {
                let ptype = if count > 2 { fields[2] } else { "" };
                let usage = if count > 9 { fields[9] } else { "" };
                let threat = if count > 13 {
                    fields[13]
                } else if count > 8 {
                    fields[..count]
                        .iter()
                        .copied()
                        .find(|&s| {
                            s.contains("SPAM") || s.contains("SCANNER") || s.contains("BOTNET")
                        })
                        .unwrap_or("")
                } else {
                    ""
                };
                parse_px_flags(ptype, usage, threat)
            } else {
                0
            };

            return Some(RawPxRecord {
                ip_from,
                ip_to,
                isp_idx,
                asn,
                flags,
            });
        }
    }
}

/// High-throughput zero-allocation GeoIP CSV streaming iterator (IPv6).
pub struct GeoRecordV6Iter<'a, R> {
    reader: R,
    line_buf: String,
    has_country: bool,
    has_region: bool,
    has_city: bool,
    has_coords: bool,
    cities: &'a mut StringPool,
    regions: &'a mut StringPool,
    prune_empty: bool,
}

impl<'a, R: BufRead> Iterator for GeoRecordV6Iter<'a, R> {
    type Item = RawGeoRecordV6;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line_buf.clear();
            let bytes_read = self.reader.read_line(&mut self.line_buf).ok()?;
            if bytes_read == 0 {
                return None;
            }
            let line = self.line_buf.trim();
            if line.is_empty() {
                continue;
            }

            let mut fields = [""; 16];
            let count = parse_csv_row_fixed(line, &mut fields);
            if count < 2 {
                continue;
            }

            let ip_from = match fields[0].parse::<u128>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ip_to = match fields[1].parse::<u128>() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let mut country = *b"--";
            if self.has_country && count > 2 {
                let cc = fields[2].as_bytes();
                if cc.len() >= 2 {
                    country = [cc[0], cc[1]];
                }
            }

            let reg_idx = if self.has_region && count > 4 {
                let raw = self.regions.get_or_insert(fields[4], self.prune_empty);
                if raw <= u16::MAX as u32 {
                    raw as u16
                } else {
                    0
                }
            } else {
                0
            };

            let city_idx = if self.has_city && count > 5 {
                self.cities.get_or_insert(fields[5], self.prune_empty)
            } else {
                0
            };

            let (lat_fixed, lon_fixed) = if self.has_coords && count > 7 {
                (safe_parse_latlon(fields[6]), safe_parse_latlon(fields[7]))
            } else {
                (0, 0)
            };

            return Some(RawGeoRecordV6 {
                ip_from,
                ip_to,
                city_idx,
                reg_idx,
                country,
                lat_fixed,
                lon_fixed,
            });
        }
    }
}

/// High-throughput zero-allocation Proxy/Threat CSV streaming iterator (IPv6).
pub struct PxRecordV6Iter<'a, R> {
    reader: R,
    line_buf: String,
    has_isp: bool,
    has_asn: bool,
    has_threats: bool,
    isps: &'a mut StringPool,
    prune_empty: bool,
}

impl<'a, R: BufRead> Iterator for PxRecordV6Iter<'a, R> {
    type Item = RawPxRecordV6;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line_buf.clear();
            let bytes_read = self.reader.read_line(&mut self.line_buf).ok()?;
            if bytes_read == 0 {
                return None;
            }
            let line = self.line_buf.trim();
            if line.is_empty() {
                continue;
            }

            let mut fields = [""; 16];
            let count = parse_csv_row_fixed(line, &mut fields);
            if count < 2 {
                continue;
            }

            let ip_from = match fields[0].parse::<u128>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ip_to = match fields[1].parse::<u128>() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let isp_idx = if self.has_isp && count > 7 {
                let raw = self.isps.get_or_insert(fields[7], self.prune_empty);
                if raw <= u16::MAX as u32 {
                    raw as u16
                } else {
                    0
                }
            } else {
                0
            };

            let asn = if self.has_asn && count > 10 {
                safe_parse_asn(fields[10])
            } else {
                0
            };

            let flags = if self.has_threats {
                let ptype = if count > 2 { fields[2] } else { "" };
                let usage = if count > 9 { fields[9] } else { "" };
                let threat = if count > 13 {
                    fields[13]
                } else if count > 8 {
                    fields[..count]
                        .iter()
                        .copied()
                        .find(|&s| {
                            s.contains("SPAM") || s.contains("SCANNER") || s.contains("BOTNET")
                        })
                        .unwrap_or("")
                } else {
                    ""
                };
                parse_px_flags(ptype, usage, threat)
            } else {
                0
            };

            return Some(RawPxRecordV6 {
                ip_from,
                ip_to,
                isp_idx,
                asn,
                flags,
            });
        }
    }
}

pub fn stream_geo_file<'a, P: AsRef<Path>>(
    path: P,
    features: FeatureMask,
    cities: &'a mut StringPool,
    regions: &'a mut StringPool,
    prune_empty: bool,
) -> Result<GeoRecordIter<'a, BufReader<File>>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(512 * 1024, file);
    Ok(GeoRecordIter {
        reader,
        line_buf: String::with_capacity(512),
        has_country: features.has_country(),
        has_region: features.has_region(),
        has_city: features.has_city(),
        has_coords: features.has_coords(),
        cities,
        regions,
        prune_empty,
    })
}

pub fn stream_px_file<'a, P: AsRef<Path>>(
    path: P,
    features: FeatureMask,
    isps: &'a mut StringPool,
    prune_empty: bool,
) -> Result<PxRecordIter<'a, BufReader<File>>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(512 * 1024, file);
    Ok(PxRecordIter {
        reader,
        line_buf: String::with_capacity(512),
        has_isp: features.has_isp(),
        has_asn: features.has_asn(),
        has_threats: features.has_threats(),
        isps,
        prune_empty,
    })
}

pub fn stream_geo_file_v6<'a, P: AsRef<Path>>(
    path: P,
    features: FeatureMask,
    cities: &'a mut StringPool,
    regions: &'a mut StringPool,
    prune_empty: bool,
) -> Result<GeoRecordV6Iter<'a, BufReader<File>>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(512 * 1024, file);
    Ok(GeoRecordV6Iter {
        reader,
        line_buf: String::with_capacity(512),
        has_country: features.has_country(),
        has_region: features.has_region(),
        has_city: features.has_city(),
        has_coords: features.has_coords(),
        cities,
        regions,
        prune_empty,
    })
}

pub fn stream_px_file_v6<'a, P: AsRef<Path>>(
    path: P,
    features: FeatureMask,
    isps: &'a mut StringPool,
    prune_empty: bool,
) -> Result<PxRecordV6Iter<'a, BufReader<File>>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(512 * 1024, file);
    Ok(PxRecordV6Iter {
        reader,
        line_buf: String::with_capacity(512),
        has_isp: features.has_isp(),
        has_asn: features.has_asn(),
        has_threats: features.has_threats(),
        isps,
        prune_empty,
    })
}
