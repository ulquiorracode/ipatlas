use std::ffi::CString;
use std::ptr;

use ipatlas_adapter_c::{
    ipatlas_close, ipatlas_is_datacenter_u32, ipatlas_is_threat_u32, ipatlas_lookup_country_u32,
    ipatlas_lookup_flags_u32, ipatlas_open, ipatlas_open_verified,
};
use ipatlas_core::{compile, CompilerOptions};
use tempfile::tempdir;

#[test]
fn test_c_abi_end_to_end_lifecycle() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("geo.csv");
    let px_path = dir.path().join("px.csv");
    let out_bin = dir.path().join("c_test.bin");

    // Sample IP: 1.2.3.4 (US, Los Angeles, Datacenter + Proxy)
    let ip_u32 = 0x01020304u32;
    std::fs::write(
        &db_path,
        format!("{ip_u32},{ip_u32},US,United States,CA,Los Angeles,34.05,-118.25\n"),
    )
    .unwrap();
    std::fs::write(&px_path, format!("{ip_u32},{ip_u32},DCH,CloudISP\n")).unwrap();

    let opts = CompilerOptions::new(&out_bin)
        .geo(Some(&db_path))
        .proxy(Some(&px_path));
    compile(opts).unwrap();

    // 1. C-ABI open and open_verified
    let c_path = CString::new(out_bin.to_str().unwrap()).unwrap();
    let handle_verified = unsafe { ipatlas_open_verified(c_path.as_ptr()) };
    assert!(!handle_verified.is_null());
    unsafe { ipatlas_close(handle_verified) };

    let handle = unsafe { ipatlas_open(c_path.as_ptr()) };
    assert!(!handle.is_null());

    // 2. Query flags and predicates with unambiguous return code
    let mut flags: u32 = 0;
    let found = unsafe { ipatlas_lookup_flags_u32(handle, ip_u32, &mut flags as *mut u32) };
    assert_eq!(found, 1);
    assert_ne!(flags, 0);

    let is_dch = unsafe { ipatlas_is_datacenter_u32(handle, ip_u32) };
    assert_eq!(is_dch, 1);

    let is_threat = unsafe { ipatlas_is_threat_u32(handle, ip_u32) };
    assert_eq!(is_threat, 1);

    // 3. Query country
    let mut country_buf = [0i8; 4];
    let res = unsafe { ipatlas_lookup_country_u32(handle, ip_u32, country_buf.as_mut_ptr()) };
    assert_eq!(res, 1);
    let country_str = unsafe { std::ffi::CStr::from_ptr(country_buf.as_ptr()) }
        .to_str()
        .unwrap();
    assert_eq!(country_str, "US");

    // 4. Query non-existent IP
    let mut flags_missing: u32 = 999;
    let found_missing =
        unsafe { ipatlas_lookup_flags_u32(handle, 0x09090909, &mut flags_missing as *mut u32) };
    assert_eq!(found_missing, 0);
    assert_eq!(flags_missing, 0);

    let res_none =
        unsafe { ipatlas_lookup_country_u32(handle, 0x09090909, country_buf.as_mut_ptr()) };
    assert_eq!(res_none, 0);

    // 5. C-ABI close
    unsafe {
        ipatlas_close(handle);
    }
}

#[test]
fn test_c_abi_negative_safety_and_null_defense() {
    // 1. Null path handling
    let handle_null = unsafe { ipatlas_open(ptr::null()) };
    assert!(handle_null.is_null(), "ipatlas_open(NULL) must return NULL");

    let handle_null_v = unsafe { ipatlas_open_verified(ptr::null()) };
    assert!(
        handle_null_v.is_null(),
        "ipatlas_open_verified(NULL) must return NULL"
    );

    // 2. Non-existent file path
    let bad_path = CString::new("this_file_does_not_exist_at_all.bin").unwrap();
    let handle_bad = unsafe { ipatlas_open(bad_path.as_ptr()) };
    assert!(
        handle_bad.is_null(),
        "ipatlas_open(missing) must return NULL"
    );

    let handle_bad_v = unsafe { ipatlas_open_verified(bad_path.as_ptr()) };
    assert!(
        handle_bad_v.is_null(),
        "ipatlas_open_verified(missing) must return NULL"
    );

    // 3. Corrupted binary file path for open_verified
    let dir = tempdir().unwrap();
    let corrupted_file = dir.path().join("corrupted.bin");
    std::fs::write(&corrupted_file, b"random corrupted non-database junk data").unwrap();
    let c_corrupt = CString::new(corrupted_file.to_str().unwrap()).unwrap();

    let handle_corrupt_v = unsafe { ipatlas_open_verified(c_corrupt.as_ptr()) };
    assert!(
        handle_corrupt_v.is_null(),
        "ipatlas_open_verified(corrupted) must return NULL"
    );

    // 4. Safe No-op on NULL handle deallocation (double close / null close)
    unsafe {
        ipatlas_close(ptr::null_mut());
    }

    // 5. Lookup on NULL handle
    let mut flags: u32 = 1234;
    let found =
        unsafe { ipatlas_lookup_flags_u32(ptr::null(), 0x01020304, &mut flags as *mut u32) };
    assert_eq!(found, 0, "Lookup on NULL handle must return 0");
    assert_eq!(flags, 0, "Flags must be written to 0 on NULL handle");

    // Null out pointer
    let found_null_ptr =
        unsafe { ipatlas_lookup_flags_u32(ptr::null(), 0x01020304, ptr::null_mut()) };
    assert_eq!(found_null_ptr, 0);

    // Predicates on NULL handle
    let is_threat = unsafe { ipatlas_is_threat_u32(ptr::null(), 0x01020304) };
    assert_eq!(is_threat, 0, "is_threat on NULL handle must return 0");

    let is_dch = unsafe { ipatlas_is_datacenter_u32(ptr::null(), 0x01020304) };
    assert_eq!(is_dch, 0, "is_datacenter on NULL handle must return 0");

    // Country on NULL handle
    let mut country_buf = [0i8; 4];
    let res =
        unsafe { ipatlas_lookup_country_u32(ptr::null(), 0x01020304, country_buf.as_mut_ptr()) };
    assert_eq!(res, 0, "lookup_country on NULL handle must return 0");

    let res_null_buf =
        unsafe { ipatlas_lookup_country_u32(ptr::null(), 0x01020304, ptr::null_mut()) };
    assert_eq!(res_null_buf, 0);
}

#[test]
fn test_c_abi_non_utf8_path_defense() {
    let bad_bytes: &[u8] = &[0xFF, 0xFE, 0xFD, 0x80, 0x00];
    let handle = unsafe { ipatlas_open(bad_bytes.as_ptr() as *const std::ffi::c_char) };
    assert!(handle.is_null(), "Non-UTF8 path must safely return NULL");

    let handle_v = unsafe { ipatlas_open_verified(bad_bytes.as_ptr() as *const std::ffi::c_char) };
    assert!(handle_v.is_null(), "Non-UTF8 path must safely return NULL");
}

#[test]
fn test_c_abi_empty_string_path_defense() {
    let empty_path = CString::new("").unwrap();
    let handle = unsafe { ipatlas_open(empty_path.as_ptr()) };
    assert!(handle.is_null(), "Empty string path must return NULL");

    let handle_v = unsafe { ipatlas_open_verified(empty_path.as_ptr()) };
    assert!(handle_v.is_null(), "Empty string path must return NULL");
}

#[test]
fn test_c_abi_multithreaded_concurrent_lookup() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("geo_mt.csv");
    let out_bin = dir.path().join("c_mt.bin");

    let ip_u32 = 0x01020304u32;
    std::fs::write(
        &db_path,
        format!("{ip_u32},{ip_u32},US,United States,CA,Los Angeles,34.05,-118.25\n"),
    )
    .unwrap();

    let opts = CompilerOptions::new(&out_bin).geo(Some(&db_path));
    compile(opts).unwrap();

    let c_path = CString::new(out_bin.to_str().unwrap()).unwrap();
    let handle = unsafe { ipatlas_open(c_path.as_ptr()) };
    assert!(!handle.is_null());

    let handle_raw = handle as usize;
    let mut threads = Vec::new();

    for _ in 0..8 {
        let t = std::thread::spawn(move || {
            let h = handle_raw as *const ipatlas_adapter_c::IpAtlasHandle;
            for _ in 0..500 {
                let mut flags = 0u32;
                let found = unsafe { ipatlas_lookup_flags_u32(h, ip_u32, &mut flags) };
                assert_eq!(found, 1);

                let mut country_buf = [0i8; 4];
                let res =
                    unsafe { ipatlas_lookup_country_u32(h, ip_u32, country_buf.as_mut_ptr()) };
                assert_eq!(res, 1);
            }
        });
        threads.push(t);
    }

    for t in threads {
        t.join().unwrap();
    }

    unsafe { ipatlas_close(handle) };
}
