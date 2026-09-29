"""
GRLG (GoldSrc Real-time Lite Geo)
High-performance binary GeoIP and Proxy/VPN threat database format.
"""

__version__ = "0.1.0"

from .reader import GrlgReader, GeoRecord, GeoFlags
from .compiler import compile_database

__all__ = ["GrlgReader", "GeoRecord", "GeoFlags", "compile_database", "__version__"]
