use crate::models::features::FeatureMask;

/// Canonical database compilation presets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    Full,
    City,
    Firewall,
    Country,
    Threats,
}

impl Preset {
    pub fn feature_mask(&self) -> FeatureMask {
        match self {
            Self::Full => FeatureMask(FeatureMask::ALL),
            Self::City => FeatureMask(
                FeatureMask::COUNTRY
                    | FeatureMask::REGION
                    | FeatureMask::CITY
                    | FeatureMask::COORDS,
            ),
            Self::Firewall => {
                FeatureMask(FeatureMask::COUNTRY | FeatureMask::ASN | FeatureMask::THREATS)
            }
            Self::Country => FeatureMask(FeatureMask::COUNTRY),
            Self::Threats => FeatureMask(FeatureMask::ASN | FeatureMask::THREATS),
        }
    }

    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "full" => Some(Self::Full),
            "city" => Some(Self::City),
            "firewall" => Some(Self::Firewall),
            "country" => Some(Self::Country),
            "threats" => Some(Self::Threats),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::City => "city",
            Self::Firewall => "firewall",
            Self::Country => "country",
            Self::Threats => "threats",
        }
    }
}
