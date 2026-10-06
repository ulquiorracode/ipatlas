//! C-ABI Foreign Function Interface (FFI) for IPAtlas.
//!
//! Exposes zero-allocation, thread-safe, panic-free C functions for embedding
//! IPAtlas into C, C++, Nginx, HAProxy, Envoy, Go, and Python runtimes.

use std::ffi::{c_char, c_int, CStr};
use std::panic::catch_unwind;
use std::ptr;

use ipatlas_core::IpAtlasReader;

/// Opaque pointer handle to an open [`IpAtlasReader`] instance.
#[repr(C)]
pub struct IpAtlasHandle {
    _private: [u8; 0],
}

/// Opens an IPAtlas database from a file path using fast header validation.
///
/// # Safety
/// `path` must be a valid, null-terminated C string.
/// Returns a non-null pointer on success, or `NULL` if opening or validation fails.
#[no_mangle]
pub unsafe extern "C" fn ipatlas_open(path: *const c_char) -> *mut IpAtlasHandle {
    let result = catch_unwind(|| {
        if path.is_null() {
            return ptr::null_mut();
        }
        let c_str = unsafe { CStr::from_ptr(path) };
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        match IpAtlasReader::open(path_str) {
            Ok(reader) => Box::into_raw(Box::new(reader)) as *mut IpAtlasHandle,
            Err(_) => ptr::null_mut(),
        }
    });
    result.unwrap_or(ptr::null_mut())
}

/// Opens and fully verifies the integrity (checksums + range sorting) of an IPAtlas database.
///
/// Recommended for cold boot in mission-critical environments (Nginx/Envoy workers).
///
/// # Safety
/// `path` must be a valid, null-terminated C string.
/// Returns a non-null pointer on success, or `NULL` if verification fails.
#[no_mangle]
pub unsafe extern "C" fn ipatlas_open_verified(path: *const c_char) -> *mut IpAtlasHandle {
    let result = catch_unwind(|| {
        if path.is_null() {
            return ptr::null_mut();
        }
        let c_str = unsafe { CStr::from_ptr(path) };
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        match IpAtlasReader::open_verified(path_str) {
            Ok(reader) => Box::into_raw(Box::new(reader)) as *mut IpAtlasHandle,
            Err(_) => ptr::null_mut(),
        }
    });
    result.unwrap_or(ptr::null_mut())
}

/// Closes and deallocates an open IPAtlas database handle.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`ipatlas_open`], or `NULL` (no-op).
#[no_mangle]
pub unsafe extern "C" fn ipatlas_close(handle: *mut IpAtlasHandle) {
    let _ = catch_unwind(|| {
        if !handle.is_null() {
            unsafe {
                drop(Box::from_raw(handle as *mut IpAtlasReader));
            }
        }
    });
}

/// Fast-path lookup writing raw threat/usage flags bitmask for an IPv4 address.
///
/// Executes with zero allocations in sub-20 ns.
///
/// Returns `1` if IP was found and writes bitmask to `flags_out`.
/// Returns `0` if not found, writing `0` to `flags_out` (if non-null).
///
/// # Safety
/// `handle` must be a valid pointer to an open [`IpAtlasReader`].
/// `flags_out` must be a valid writable pointer to `uint32_t`.
#[no_mangle]
pub unsafe extern "C" fn ipatlas_lookup_flags_u32(
    handle: *const IpAtlasHandle,
    ip: u32,
    flags_out: *mut u32,
) -> c_int {
    let result = catch_unwind(|| {
        if handle.is_null() {
            if !flags_out.is_null() {
                unsafe { *flags_out = 0 };
            }
            return 0;
        }
        let reader = unsafe { &*(handle as *const IpAtlasReader) };
        match reader.lookup_flags_u32(ip) {
            Some(flags) => {
                if !flags_out.is_null() {
                    unsafe { *flags_out = flags.0 as u32 };
                }
                1
            }
            None => {
                if !flags_out.is_null() {
                    unsafe { *flags_out = 0 };
                }
                0
            }
        }
    });
    result.unwrap_or(0)
}

/// Fast predicate checking if IPv4 address is a known threat (Proxy, VPN, Tor, Botnet, Spam).
///
/// Returns 1 if true, 0 if false or not found.
///
/// # Safety
/// `handle` must be a valid pointer to an open [`IpAtlasReader`].
#[no_mangle]
pub unsafe extern "C" fn ipatlas_is_threat_u32(handle: *const IpAtlasHandle, ip: u32) -> c_int {
    let result = catch_unwind(|| {
        if handle.is_null() {
            return 0;
        }
        let reader = unsafe { &*(handle as *const IpAtlasReader) };
        if reader.is_threat_u32(ip) {
            1
        } else {
            0
        }
    });
    result.unwrap_or(0)
}

/// Fast predicate checking if IPv4 address belongs to a datacenter / cloud provider.
///
/// Returns 1 if true, 0 if false or not found.
///
/// # Safety
/// `handle` must be a valid pointer to an open [`IpAtlasReader`].
#[no_mangle]
pub unsafe extern "C" fn ipatlas_is_datacenter_u32(handle: *const IpAtlasHandle, ip: u32) -> c_int {
    let result = catch_unwind(|| {
        if handle.is_null() {
            return 0;
        }
        let reader = unsafe { &*(handle as *const IpAtlasReader) };
        if reader.is_datacenter_u32(ip) {
            1
        } else {
            0
        }
    });
    result.unwrap_or(0)
}

/// Populates `country_out` with null-terminated 2-letter ISO country code.
///
/// `country_out` must point to a buffer of at least 3 bytes (`char country[3]`).
/// Returns 1 on success, 0 on not found.
///
/// # Safety
/// `handle` must be a valid pointer to an open [`IpAtlasReader`], and `country_out`
/// must point to a valid writable buffer of at least 3 bytes.
#[no_mangle]
pub unsafe extern "C" fn ipatlas_lookup_country_u32(
    handle: *const IpAtlasHandle,
    ip: u32,
    country_out: *mut c_char,
) -> c_int {
    let result = catch_unwind(|| {
        if handle.is_null() || country_out.is_null() {
            return 0;
        }
        let reader = unsafe { &*(handle as *const IpAtlasReader) };
        if let Some(code) = reader.lookup_country_code_u32(ip) {
            let bytes = code.as_bytes();
            if bytes.len() >= 2 {
                unsafe {
                    *country_out = bytes[0] as c_char;
                    *country_out.add(1) = bytes[1] as c_char;
                    *country_out.add(2) = 0;
                }
                return 1;
            }
        }
        0
    });
    result.unwrap_or(0)
}
