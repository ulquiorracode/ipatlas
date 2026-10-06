//! Drop-in MaxMind DB (`maxminddb`) compatibility layer for IPAtlas.
//!
//! Enables applications built for `maxminddb` (GeoLite2-City / GeoIP2) to switch
//! to IPAtlas binary databases without rewriting caller application logic.
//!
//! Zero memory leaks: Models own their strings without `Box::leak`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use ipatlas_core::{GeoRecord, IpAtlasReader, ReaderError};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MaxMindDBError {
    #[error("Address not found in database")]
    AddressNotFoundError(String),
    #[error("Reader error: {0}")]
    ReaderError(#[from] ReaderError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid IP string")]
    InvalidIp,
}

pub mod geoip2 {
    use super::*;

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct Country {
        pub iso_code: Option<String>,
        pub names: Option<BTreeMap<String, String>>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct City {
        pub names: Option<BTreeMap<String, String>>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct Location {
        pub latitude: Option<f64>,
        pub longitude: Option<f64>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct Subdivision {
        pub iso_code: Option<String>,
        pub names: Option<BTreeMap<String, String>>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct CityRecord {
        pub city: Option<City>,
        pub country: Option<Country>,
        pub location: Option<Location>,
        pub subdivisions: Option<Vec<Subdivision>>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct CountryRecord {
        pub country: Option<Country>,
    }
}

/// Drop-in compatible `Reader` mirroring the official `maxminddb::Reader` interface.
pub struct Reader {
    inner: IpAtlasReader,
}

impl Reader {
    /// Opens an IPAtlas database from file (accepting path like maxminddb::Reader::open_readfile).
    pub fn open_readfile<P: AsRef<Path>>(path: P) -> Result<Self, MaxMindDBError> {
        let inner = IpAtlasReader::open(path)?;
        Ok(Self { inner })
    }

    /// Primary lookup method mirroring `reader.lookup::<geoip2::CityRecord>(ip)`.
    pub fn lookup<T: FromIpAtlasRecord>(&self, ip: IpAddr) -> Result<T, MaxMindDBError> {
        match self.inner.lookup(ip) {
            Some(rec) => Ok(T::from_record(rec)),
            None => Err(MaxMindDBError::AddressNotFoundError(ip.to_string())),
        }
    }
}

/// Conversion trait mapping IPAtlas [`GeoRecord`] into GeoIP2 models.
pub trait FromIpAtlasRecord {
    fn from_record(rec: GeoRecord) -> Self;
}

impl FromIpAtlasRecord for geoip2::CityRecord {
    fn from_record(rec: GeoRecord) -> Self {
        let mut country_names = BTreeMap::new();
        country_names.insert("en".to_string(), rec.country.clone());

        let country = geoip2::Country {
            iso_code: Some(rec.country),
            names: Some(country_names),
        };

        let mut city_names = BTreeMap::new();
        city_names.insert("en".to_string(), rec.city);
        let city = geoip2::City {
            names: Some(city_names),
        };

        let location = geoip2::Location {
            latitude: Some(rec.latitude as f64),
            longitude: Some(rec.longitude as f64),
        };

        let mut sub_names = BTreeMap::new();
        sub_names.insert("en".to_string(), rec.region);
        let subdivisions = vec![geoip2::Subdivision {
            iso_code: None,
            names: Some(sub_names),
        }];

        geoip2::CityRecord {
            city: Some(city),
            country: Some(country),
            location: Some(location),
            subdivisions: Some(subdivisions),
        }
    }
}

impl FromIpAtlasRecord for geoip2::CountryRecord {
    fn from_record(rec: GeoRecord) -> Self {
        let mut country_names = BTreeMap::new();
        country_names.insert("en".to_string(), rec.country.clone());

        let country = geoip2::Country {
            iso_code: Some(rec.country),
            names: Some(country_names),
        };

        geoip2::CountryRecord {
            country: Some(country),
        }
    }
}
