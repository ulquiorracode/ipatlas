//! MaxMind GeoLite2 CSV Ingestion SPI Adapter for IPAtlas.
//!
//! Parses MaxMind GeoLite2 City / Country Blocks and Locations CSV exports
//! and maps them into [`IngestRecordV4`] via [`DatasetIngestionAdapter`].

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use ipatlas_core::{DatasetIngestionAdapter, IngestRecordV4};

/// Normalized geographic location entry parsed from MaxMind `GeoLite2-City-Locations-en.csv`.
#[derive(Clone, Debug, Default)]
pub struct LocationEntry {
    pub country_code: [u8; 2],
    pub region_name: Option<String>,
    pub city_name: Option<String>,
}

/// MaxMind GeoLite2 CSV Ingestion Adapter implementing [`DatasetIngestionAdapter`].
pub struct MaxMindCityAdapter {
    blocks_path: std::path::PathBuf,
    locations: HashMap<u32, LocationEntry>,
}

impl MaxMindCityAdapter {
    /// Loads locations lookup dictionary from `GeoLite2-City-Locations-en.csv`
    /// and prepares adapter for streaming blocks.
    pub fn open(
        blocks_csv: impl AsRef<Path>,
        locations_csv: impl AsRef<Path>,
    ) -> Result<Self, std::io::Error> {
        // Validate blocks file existence and accessibility upfront to prevent silent empty iteration
        let _ = File::open(blocks_csv.as_ref())?;

        let loc_file = File::open(locations_csv)?;
        let reader = BufReader::new(loc_file);
        let mut locations = HashMap::new();

        for line_res in reader.lines() {
            let line = line_res?;
            if line.is_empty() || line.starts_with("geoname_id") {
                continue;
            }
            // Parse CSV with quotes handling
            let fields = parse_csv_line(&line);
            if fields.len() > 10 {
                if let Ok(geoname_id) = fields[0].parse::<u32>() {
                    let country_str = fields[4].trim();
                    let country_code = if country_str.len() >= 2 {
                        let b = country_str.as_bytes();
                        [b[0], b[1]]
                    } else {
                        *b"--"
                    };
                    let region_name = if !fields[7].is_empty() {
                        Some(fields[7].to_string())
                    } else {
                        None
                    };
                    let city_name = if !fields[10].is_empty() {
                        Some(fields[10].to_string())
                    } else {
                        None
                    };

                    locations.insert(
                        geoname_id,
                        LocationEntry {
                            country_code,
                            region_name,
                            city_name,
                        },
                    );
                }
            }
        }

        Ok(Self {
            blocks_path: blocks_csv.as_ref().to_path_buf(),
            locations,
        })
    }
}

impl DatasetIngestionAdapter for MaxMindCityAdapter {
    fn parse_v4(&mut self) -> Box<dyn Iterator<Item = IngestRecordV4> + '_> {
        let file = match File::open(&self.blocks_path) {
            Ok(f) => f,
            Err(_) => return Box::new(std::iter::empty()),
        };
        let reader = BufReader::new(file);

        let iter = reader.lines().filter_map(|line_res| {
            let line = line_res.ok()?;
            if line.is_empty() || line.starts_with("network") {
                return None;
            }
            let fields = parse_csv_line(&line);
            if fields.is_empty() {
                return None;
            }

            let cidr = fields[0].trim();
            let mut record = IngestRecordV4::from_cidr(cidr).ok()?;

            // Match geoname_id (fields[1])
            if fields.len() > 1 {
                if let Ok(geoname_id) = fields[1].parse::<u32>() {
                    if let Some(loc) = self.locations.get(&geoname_id) {
                        record.country = loc.country_code;
                        record.region = loc.region_name.clone();
                        record.city = loc.city_name.clone();
                    }
                }
            }

            // Coordinates: latitude (fields[7]), longitude (fields[8]) if available
            if fields.len() > 8 {
                if let Ok(lat) = fields[7].parse::<f32>() {
                    record.latitude = lat;
                }
                if let Ok(lon) = fields[8].parse::<f32>() {
                    record.longitude = lon;
                }
            }

            Some(record)
        });

        Box::new(iter)
    }
}

fn parse_csv_line(s: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in s.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    fields.push(current.trim().to_string());
    fields
}
