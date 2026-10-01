"""
IPAtlas: Ultra-fast Zero-Copy Binary GeoIP & Proxy Threat Database.
"""

__version__ = "0.3.0"

from .reader import IpAtlasReader, GrlgReader, GeoRecord, GeoFlags
from .compiler import (
    compile_database,
    parse_features,
    PRESETS,
    FEATURE_COUNTRY,
    FEATURE_REGION,
    FEATURE_CITY,
    FEATURE_COORDS,
    FEATURE_ISP,
    FEATURE_ASN,
    FEATURE_THREATS,
    ALL_FEATURES,
)

__all__ = [
    "IpAtlasReader",
    "GrlgReader",
    "GeoRecord",
    "GeoFlags",
    "compile_database",
    "parse_features",
    "PRESETS",
    "FEATURE_COUNTRY",
    "FEATURE_REGION",
    "FEATURE_CITY",
    "FEATURE_COORDS",
    "FEATURE_ISP",
    "FEATURE_ASN",
    "FEATURE_THREATS",
    "ALL_FEATURES",
    "__version__",
]
