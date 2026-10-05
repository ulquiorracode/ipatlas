use ipatlas::compiler::succinct::SuccinctIntervalTable;
use ipatlas::models::{Ipv4Range, ProfileGen4};

#[test]
fn test_succinct_elias_fano_compression_and_lookup() {
    let mut ranges = Vec::new();
    let mut profiles = Vec::new();

    // Create 1,000 realistic non-overlapping intervals
    let mut curr_ip = 16_777_216u32; // 1.0.0.0
    for i in 0..1000 {
        let span = 256;
        let to = curr_ip + span - 1;
        let prof_id = (i % 10) as u32;
        ranges.push(Ipv4Range::new(curr_ip, to, prof_id));
        curr_ip = to + 1;
    }

    for i in 0..10 {
        profiles.push(ProfileGen4::new(i, 100 + i, *b"US", 1, 1, 0, 3700, -12200));
    }

    let raw_v4_bytes = ranges.len() * 12; // 12,000 bytes in V4-Standard
    let compact_bytes = ranges.len() * 8; // 8,000 bytes in V4-Compact

    let table = SuccinctIntervalTable::build(&ranges, profiles.clone());
    let succinct_bytes = table.index_size_bytes();

    println!("\n=== Concrete Compression Measurement (1,000 ranges) ===");
    println!("V4-Standard (12B): {:>6} bytes (100.0%)", raw_v4_bytes);
    println!(
        "V4-Compact   (8B): {:>6} bytes ({:.1}%)",
        compact_bytes,
        (compact_bytes as f64 / raw_v4_bytes as f64) * 100.0
    );
    println!(
        "V5-Succinct (E-F): {:>6} bytes ({:.1}%)",
        succinct_bytes,
        (succinct_bytes as f64 / raw_v4_bytes as f64) * 100.0
    );

    // Verify boundary decoding correctness for all 1,000 intervals
    for (i, r) in ranges.iter().enumerate() {
        let decoded_from = table.get_ip_from(i);
        assert_eq!(
            decoded_from, r.ip_from,
            "Decoded IP mismatch at index {}",
            i
        );
    }

    // Verify lookup accuracy
    for (i, r) in ranges.iter().enumerate() {
        let prof = table.lookup(r.ip_from + 10).expect("IP must be found");
        let expected_prof = &profiles[i % 10];
        assert_eq!(prof.asn, expected_prof.asn);
        assert_eq!(prof.country, expected_prof.country);
    }
}
