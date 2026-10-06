"""
IPAtlas Python Client via ctypes.

Zero-dependency, zero-copy GeoIP and threat detection client wrapping
the native IPAtlas C-ABI shared library.
"""

from __future__ import annotations

import ctypes
import os
import platform
import socket
import struct
from typing import Optional


def _find_library() -> str:
    """Finds the IPAtlas C-ABI shared library."""
    # 1. Explicit environment variable
    if env_path := os.environ.get("IPATLAS_LIB_PATH"):
        if os.path.exists(env_path):
            return env_path

    # 2. System-dependent library name
    system = platform.system()
    if system == "Windows":
        lib_name = "ipatlas_adapter_c.dll"
    elif system == "Darwin":
        lib_name = "libipatlas_adapter_c.dylib"
    else:
        lib_name = "libipatlas_adapter_c.so"

    # 3. Standard search paths relative to workspace or package
    base_dir = os.path.abspath(os.path.dirname(__file__))
    candidates = [
        # In current directory
        os.path.join(base_dir, lib_name),
        # Target release/debug build directories
        os.path.join(base_dir, "..", "..", "..", "target", "release", lib_name),
        os.path.join(base_dir, "..", "..", "..", "target", "debug", lib_name),
        # In lib directory
        os.path.join(base_dir, "lib", lib_name),
    ]

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    return lib_name


class _IpAtlasC:
    """Loaded C-ABI function signatures."""

    def __init__(self, lib_path: Optional[str] = None):
        path = lib_path or _find_library()
        self.cdll = ctypes.CDLL(path)

        # ipatlas_open(const char* path) -> IpAtlasHandle*
        self.cdll.ipatlas_open.argtypes = [ctypes.c_char_p]
        self.cdll.ipatlas_open.restype = ctypes.c_void_p

        # ipatlas_open_verified(const char* path) -> IpAtlasHandle*
        self.cdll.ipatlas_open_verified.argtypes = [ctypes.c_char_p]
        self.cdll.ipatlas_open_verified.restype = ctypes.c_void_p

        # ipatlas_close(IpAtlasHandle* handle)
        self.cdll.ipatlas_close.argtypes = [ctypes.c_void_p]
        self.cdll.ipatlas_close.restype = None

        # ipatlas_lookup_flags_u32(const IpAtlasHandle* handle, uint32_t ip, uint32_t* flags_out) -> int
        self.cdll.ipatlas_lookup_flags_u32.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self.cdll.ipatlas_lookup_flags_u32.restype = ctypes.c_int

        # ipatlas_is_threat_u32(const IpAtlasHandle* handle, uint32_t ip) -> int
        self.cdll.ipatlas_is_threat_u32.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.cdll.ipatlas_is_threat_u32.restype = ctypes.c_int

        # ipatlas_is_datacenter_u32(const IpAtlasHandle* handle, uint32_t ip) -> int
        self.cdll.ipatlas_is_datacenter_u32.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.cdll.ipatlas_is_datacenter_u32.restype = ctypes.c_int

        # ipatlas_lookup_country_u32(const IpAtlasHandle* handle, uint32_t ip, char* country_out) -> int
        self.cdll.ipatlas_lookup_country_u32.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
        ]
        self.cdll.ipatlas_lookup_country_u32.restype = ctypes.c_int


_C_API: Optional[_IpAtlasC] = None


def _get_c_api(lib_path: Optional[str] = None) -> _IpAtlasC:
    global _C_API
    if _C_API is None or lib_path is not None:
        _C_API = _IpAtlasC(lib_path)
    return _C_API


def _ipv4_to_u32(ip: str) -> int:
    """Converts an IPv4 string address to 32-bit unsigned integer (host byte order)."""
    if ":" in ip:
        raise ValueError(
            f"IPv6 address '{ip}' is not supported in the C-ABI fast path yet (IPv4 only). "
            "Use the Rust native library or HTTP microservice for IPv6."
        )
    try:
        packed = socket.inet_aton(ip)
    except socket.error as e:
        raise ValueError(f"Invalid IPv4 address format: '{ip}'") from e
    return struct.unpack("!I", packed)[0]


class IpAtlasDatabase:
    """High-level Python wrapper for an open IPAtlas binary database."""

    def __init__(self, handle: ctypes.c_void_p, c_api: _IpAtlasC):
        self._handle = handle
        self._c = c_api

    @classmethod
    def open(cls, path: str, verified: bool = False, lib_path: Optional[str] = None) -> IpAtlasDatabase:
        """Opens an IPAtlas binary database from file.

        Args:
            path: Path to .bin database.
            verified: If True, performs complete cryptographic CRC32 & order verification.
            lib_path: Optional custom path to libipatlas_adapter_c shared library.
        """
        c = _get_c_api(lib_path)
        encoded_path = path.encode("utf-8")
        if verified:
            handle = c.cdll.ipatlas_open_verified(encoded_path)
        else:
            handle = c.cdll.ipatlas_open(encoded_path)

        if not handle:
            raise IOError(f"Failed to open IPAtlas database at: {path}")

        return cls(handle, c)

    def close(self) -> None:
        """Closes and releases memory resources."""
        if self._handle:
            self._c.cdll.ipatlas_close(self._handle)
            self._handle = None

    def __enter__(self) -> IpAtlasDatabase:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def lookup_flags(self, ip: str) -> Optional[int]:
        """Returns raw bitmask flags for IPv4 address, or None if not found."""
        if not self._handle:
            raise RuntimeError("Database handle is closed")
        ip_u32 = _ipv4_to_u32(ip)
        flags_out = ctypes.c_uint32(0)
        found = self._c.cdll.ipatlas_lookup_flags_u32(self._handle, ip_u32, ctypes.byref(flags_out))
        if found == 1:
            return flags_out.value
        return None

    def is_threat(self, ip: str) -> bool:
        """Checks if IPv4 is a known threat (Proxy, VPN, Tor, Botnet, Spam, Hosting)."""
        if not self._handle:
            raise RuntimeError("Database handle is closed")
        ip_u32 = _ipv4_to_u32(ip)
        return bool(self._c.cdll.ipatlas_is_threat_u32(self._handle, ip_u32))

    def is_datacenter(self, ip: str) -> bool:
        """Checks if IPv4 belongs to a known datacenter or cloud hosting provider."""
        if not self._handle:
            raise RuntimeError("Database handle is closed")
        ip_u32 = _ipv4_to_u32(ip)
        return bool(self._c.cdll.ipatlas_is_datacenter_u32(self._handle, ip_u32))

    def lookup_country(self, ip: str) -> Optional[str]:
        """Returns 2-letter ISO country code for IPv4 address, or None if not found."""
        if not self._handle:
            raise RuntimeError("Database handle is closed")
        ip_u32 = _ipv4_to_u32(ip)
        buf = ctypes.create_string_buffer(4)
        found = self._c.cdll.ipatlas_lookup_country_u32(self._handle, ip_u32, buf)
        if found == 1:
            return buf.value.decode("ascii")
        return None
