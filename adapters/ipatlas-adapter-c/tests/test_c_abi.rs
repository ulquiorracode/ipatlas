use std::ffi::CString;

use ipatlas_adapter_c::{
    ipatlas_close, ipatlas_is_datacenter_u32, ipatlas_is_threat_u32, ipatlas_lookup_country_u32,
    ipatlas_lookup_flags_u32, ipatlas_open,
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

    // 1. C-ABI open
    let c_path = CString::new(out_bin.to_str().unwrap()).unwrap();
    let handle = unsafe { ipatlas_open(c_path.as_ptr()) };
    assert!(!handle.is_null());

    // 2. Query flags and predicates
    let flags = unsafe { ipatlas_lookup_flags_u32(handle, ip_u32) };
    assert_ne!(flags, 0);

    let is_dch = unsafe { ipatlas_is_datacenter_u32(handle, ip_u32) };
    assert_eq!(is_dch, 1);

    let is_threat = unsafe { ipatlas_is_threat_u32(handle, ip_u32) };
    assert_eq!(is_threat, 1); // Datacenter / Cloud is treated as threat/hosting in GeoFlags

    // 3. Query country
    let mut country_buf = [0i8; 4];
    let res = unsafe { ipatlas_lookup_country_u32(handle, ip_u32, country_buf.as_mut_ptr()) };
    assert_eq!(res, 1);
    let country_str = unsafe { std::ffi::CStr::from_ptr(country_buf.as_ptr()) }
        .to_str()
        .unwrap();
    assert_eq!(country_str, "US");

    // 4. Query non-existent IP
    let res_none =
        unsafe { ipatlas_lookup_country_u32(handle, 0x09090909, country_buf.as_mut_ptr()) };
    assert_eq!(res_none, 0);

    // 5. C-ABI close
    unsafe {
        ipatlas_close(handle);
    }
}
