"""
IPAtlas: Ultra-fast Zero-Copy Binary GeoIP & Proxy Threat Database.
"""

__version__ = "0.2.0"

from .reader import IpAtlasReader, GrlgReader, GeoRecord, GeoFlags
from .compiler import compile_database

__all__ = [
    "IpAtlasReader",
    "GrlgReader",
    "GeoRecord",
    "GeoFlags",
    "compile_database",
    "__version__",
]
