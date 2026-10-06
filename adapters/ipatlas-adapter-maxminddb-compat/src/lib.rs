//! Drop-in MaxMind DB (`maxminddb`) compatibility layer for IPAtlas.
//!
//! Enables applications built for `maxminddb` (GeoLite2-City / GeoIP2) to switch
//! to IPAtlas binary databases without rewriting caller application logic.

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
    pub struct Country<'a> {
        pub iso_code: Option<&'a str>,
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct City<'a> {
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct Location {
        pub latitude: Option<f64>,
        pub longitude: Option<f64>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct Subdivision<'a> {
        pub iso_code: Option<&'a str>,
        pub names: Option<BTreeMap<&'a str, &'a str>>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct CityRecord<'a> {
        pub city: Option<City<'a>>,
        pub country: Option<Country<'a>>,
        pub location: Option<Location>,
        pub subdivisions: Option<Vec<Subdivision<'a>>>,
    }

    #[derive(Serialize, Clone, Debug, Default)]
    pub struct CountryRecord<'a> {
        pub country: Option<Country<'a>>,
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

    /// Primary lookup method mirroring `reader.lookup::<geoip2::City>(ip)`.
    pub fn lookup<'a, T: FromIpAtlasRecord<'a>>(&'a self, ip: IpAddr) -> Result<T, MaxMindDBError> {
        match self.inner.lookup(ip) {
            Some(rec) => Ok(T::from_record(rec)),
            None => Err(MaxMindDBError::AddressNotFoundError(ip.to_string())),
        }
    }
}

/// Conversion trait mapping IPAtlas [`GeoRecord`] into GeoIP2 models.
pub trait FromIpAtlasRecord<'a> {
    fn from_record(rec: GeoRecord) -> Self;
}

impl<'a> FromIpAtlasRecord<'a> for geoip2::CityRecord<'static> {
    fn from_record(rec: GeoRecord) -> Self {
        let mut country_names = BTreeMap::new();
        country_names.insert(
            "en",
            Box::leak(rec.country.clone().into_boxed_str()) as &str,
        );

        let country = geoip2::Country {
            iso_code: Some(Box::leak(rec.country.into_boxed_str())),
            names: Some(country_names),
        };

        let mut city_names = BTreeMap::new();
        city_names.insert("en", Box::leak(rec.city.clone().into_boxed_str()) as &str);
        let city = geoip2::City {
            names: Some(city_names),
        };

        let location = geoip2::Location {
            latitude: Some(rec.latitude as f64),
            longitude: Some(rec.longitude as f64),
        };

        let mut sub_names = BTreeMap::new();
        sub_names.insert("en", Box::leak(rec.region.clone().into_boxed_str()) as &str);
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

impl<'a> FromIpAtlasRecord<'a> for geoip2::CountryRecord<'static> {
    fn from_record(rec: GeoRecord) -> Self {
        let mut country_names = BTreeMap::new();
        country_names.insert(
            "en",
            Box::leak(rec.country.clone().into_boxed_str()) as &str,
        );

        let country = geoip2::Country {
            iso_code: Some(Box::leak(rec.country.into_boxed_str())),
            names: Some(country_names),
        };

        geoip2::CountryRecord {
            country: Some(country),
        }
    }
}
