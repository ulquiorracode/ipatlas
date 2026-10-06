/// Bitmask for selecting database metadata columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureMask(pub u16);

impl FeatureMask {
    pub const COUNTRY: u16 = 0x0001;
    pub const REGION: u16 = 0x0002;
    pub const CITY: u16 = 0x0004;
    pub const COORDS: u16 = 0x0008;
    pub const ISP: u16 = 0x0010;
    pub const ASN: u16 = 0x0020;
    pub const THREATS: u16 = 0x0040;

    pub const ALL: u16 = Self::COUNTRY
        | Self::REGION
        | Self::CITY
        | Self::COORDS
        | Self::ISP
        | Self::ASN
        | Self::THREATS;

    #[inline(always)]
    pub fn contains(&self, flag: u16) -> bool {
        (self.0 & flag) != 0
    }

    #[inline(always)]
    pub fn has_country(&self) -> bool {
        self.contains(Self::COUNTRY)
    }

    #[inline(always)]
    pub fn has_region(&self) -> bool {
        self.contains(Self::REGION)
    }

    #[inline(always)]
    pub fn has_city(&self) -> bool {
        self.contains(Self::CITY)
    }

    #[inline(always)]
    pub fn has_coords(&self) -> bool {
        self.contains(Self::COORDS)
    }

    #[inline(always)]
    pub fn has_isp(&self) -> bool {
        self.contains(Self::ISP)
    }

    #[inline(always)]
    pub fn has_asn(&self) -> bool {
        self.contains(Self::ASN)
    }

    #[inline(always)]
    pub fn has_threats(&self) -> bool {
        self.contains(Self::THREATS)
    }

    /// Parses comma-separated feature list (e.g. "country,asn,threats").
    pub fn parse_csv(s: &str) -> Result<Self, String> {
        let mut mask = 0u16;
        for part in s.split(',') {
            let name = part.trim().to_lowercase();
            if name.is_empty() {
                continue;
            }
            match name.as_str() {
                "country" => mask |= Self::COUNTRY,
                "region" => mask |= Self::REGION,
                "city" => mask |= Self::CITY,
                "coords" | "latlon" => mask |= Self::COORDS,
                "isp" => mask |= Self::ISP,
                "asn" => mask |= Self::ASN,
                "threats" | "proxy" => mask |= Self::THREATS,
                other => return Err(format!("Unknown feature: '{}'. Available: country, region, city, coords, isp, asn, threats", other)),
            }
        }
        Ok(Self(mask))
    }
}

impl Default for FeatureMask {
    fn default() -> Self {
        Self(Self::ALL)
    }
}
