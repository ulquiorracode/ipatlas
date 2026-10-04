use ipatlas::compiler::adapters::{
    CoalesceAdapter, CompilerStreamExt, LossyCoordsAdapter, TransformableEntry,
};
use ipatlas::compiler::sweep::MergedEntry;
use ipatlas::models::FeatureMask;

fn make_entry(from: u32, to: u32, country: [u8; 2], city: u32, lat: i16, lon: i16) -> MergedEntry {
    MergedEntry {
        ip_from: from,
        ip_to: to,
        country,
        reg_idx: 1,
        city_idx: city,
        isp_idx: 1,
        asn: 1337,
        flags: 0,
        lat_fixed: lat,
        lon_fixed: lon,
    }
}

#[test]
fn test_coalesce_adapter_directly() {
    let entries = vec![
        make_entry(100, 200, *b"US", 10, 3700, -12200),
        make_entry(201, 300, *b"US", 10, 3700, -12200), // Contiguous and identical -> merges
        make_entry(301, 400, *b"DE", 20, 5200, 1300),   // Different country -> separate
        make_entry(450, 500, *b"DE", 20, 5200, 1300),   // Non-contiguous gap (401..449) -> separate
    ];

    let merged: Vec<MergedEntry> = CoalesceAdapter::new(entries.into_iter()).collect();

    assert_eq!(merged.len(), 3);
    assert_eq!(merged[0].ip_from, 100);
    assert_eq!(merged[0].ip_to, 300);
    assert_eq!(merged[0].country, *b"US");

    assert_eq!(merged[1].ip_from, 301);
    assert_eq!(merged[1].ip_to, 400);
    assert_eq!(merged[1].country, *b"DE");

    assert_eq!(merged[2].ip_from, 450);
    assert_eq!(merged[2].ip_to, 500);
    assert_eq!(merged[2].country, *b"DE");
}

#[test]
fn test_lossy_coords_adapter_directly() {
    let entries = vec![
        make_entry(100, 200, *b"US", 10, 3712, -12234),
        make_entry(201, 300, *b"US", 10, 3714, -12236),
    ];

    // Under lossy quantization, both 3712 and 3714 quantize to 3710
    let quantized: Vec<MergedEntry> = LossyCoordsAdapter::new(entries.into_iter()).collect();
    assert_eq!(quantized[0].lat_fixed, 3710);
    assert_eq!(quantized[1].lat_fixed, 3710);

    // Fluent pipeline with compiler stream extension:
    let entries2 = vec![
        make_entry(100, 200, *b"US", 10, 3712, -12232),
        make_entry(201, 300, *b"US", 10, 3714, -12234),
    ];
    let coalesced: Vec<MergedEntry> = entries2.into_iter().quantize_coords().coalesce().collect();

    // Because quantized coordinates became equal (3710, -12230), they now coalesce into 1 interval!
    assert_eq!(coalesced.len(), 1);
    assert_eq!(coalesced[0].ip_from, 100);
    assert_eq!(coalesced[0].ip_to, 300);
}

#[test]
fn test_feature_mask_adapter_directly() {
    let mut entry = make_entry(100, 200, *b"US", 10, 3712, -12234);
    let country_only = FeatureMask(FeatureMask::COUNTRY);

    entry.apply_feature_mask(country_only);
    assert_eq!(entry.country, *b"US");
    assert_eq!(entry.city_idx, 0); // stripped
    assert_eq!(entry.reg_idx, 0); // stripped
    assert_eq!(entry.isp_idx, 0); // stripped
    assert_eq!(entry.asn, 0); // stripped
    assert_eq!(entry.lat_fixed, 0); // stripped
}
