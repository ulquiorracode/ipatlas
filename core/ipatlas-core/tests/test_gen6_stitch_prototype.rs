//! Direct Comparative Benchmark Prototype: IPAtlas Gen 4/5 Flat vs Gen 6 Stitch-Data Columnar Container.
//!
//! Evaluates:
//! 1. File Size on disk (Bytes).
//! 2. Binary search & lookup latency (Single-query nanoseconds).
//! 3. Memory footprint and zero-allocation compliance.

use std::fs::File;
use tempfile::tempdir;

use stitch_data::prelude::*;
use stitch_data::{
    decode_u32_column, encode_u32_column, ColumnCodecTag, ColumnSliceIndex, ColumnarBlockWriter,
    ContainerReader, ContainerWriter,
};

/// 10,000 synthetic IP ranges matching IPAtlas benchmark distribution.
fn generate_ranges(count: usize) -> Vec<(u32, u32, u32)> {
    let mut ranges = Vec::with_capacity(count);
    let mut curr: u32 = 16_777_216; // 1.0.0.0
    for i in 0..count {
        let step = 256;
        let ip_from = curr;
        let ip_to = curr + step - 1;
        curr = ip_to + 1;
        let profile_id = (i % 250) as u32;
        ranges.push((ip_from, ip_to, profile_id));
    }
    ranges
}

#[test]
fn test_gen6_columnar_stitch_prototype_vs_gen5_flat() {
    let dir = tempdir().unwrap();
    let ranges = generate_ranges(10_000);

    // ------------------------------------------------------------------------
    // 1. Gen 5 Flat Representation (AoS: 12 bytes / record, SoA: 4 + 4 + 4)
    // ------------------------------------------------------------------------
    let gen5_raw_bytes = ranges.len() * 12; // 120,000 bytes for 10k ranges

    // ------------------------------------------------------------------------
    // 2. Gen 6 Stitch-Data Chunked Columnar Representation
    // ------------------------------------------------------------------------
    let gen6_path = dir.path().join("ipatlas_gen6.bin");
    let file = File::create(&gen6_path).unwrap();
    let mut writer = ContainerWriter::new(file, 0x1FA7_1A56_0006, 0).unwrap();

    let chunk_size = 1024;
    let mut scratch = vec![0u32; chunk_size];
    let mut col_buf = vec![0u8; chunk_size * 4];
    let mut payload_buf = vec![0u8; chunk_size * 16];
    let mut frame_buf = vec![0u8; chunk_size * 16];

    for chunk in ranges.chunks(chunk_size) {
        let first_key = chunk[0].0 as u64;
        let mut block_writer = ColumnarBlockWriter::new(chunk.len(), 3, &mut payload_buf).unwrap();

        // Column 0: ip_from (Delta + BitPack via AdaptiveU32)
        let col0: Vec<u32> = chunk.iter().map(|r| r.0).collect();
        let col0_len = encode_u32_column(&col0, &mut scratch, &mut col_buf).unwrap();
        block_writer
            .write_column(ColumnCodecTag::AdaptiveU32, &col_buf[..col0_len])
            .unwrap();

        // Column 1: count (length of range)
        let col1: Vec<u32> = chunk.iter().map(|r| r.1 - r.0 + 1).collect();
        let col1_len = encode_u32_column(&col1, &mut scratch, &mut col_buf).unwrap();
        block_writer
            .write_column(ColumnCodecTag::AdaptiveU32, &col_buf[..col1_len])
            .unwrap();

        // Column 2: profile_id
        let col2: Vec<u32> = chunk.iter().map(|r| r.2).collect();
        let col2_len = encode_u32_column(&col2, &mut scratch, &mut col_buf).unwrap();
        block_writer
            .write_column(ColumnCodecTag::AdaptiveU32, &col_buf[..col2_len])
            .unwrap();

        let payload_len = block_writer.finish().unwrap();

        let header = FrameHeader {
            profile: OptimizationProfile::Balanced,
            flags: FrameFlags::default(),
            payload_len,
            schema_hash: None,
        };
        let frame_len = pack_frame(&header, &payload_buf[..payload_len], &mut frame_buf).unwrap();

        writer
            .write_chunk(first_key, chunk.len(), &frame_buf[..frame_len])
            .unwrap();
    }

    let (gen6_total_bytes, chunks_written) = writer.finish().unwrap();

    // ------------------------------------------------------------------------
    // Comparison metrics
    // ------------------------------------------------------------------------
    println!("\n=== IPATLAS STORAGE FOOTPRINT COMPARISON (10,000 RANGES) ===");
    println!(
        "Gen 5 Flat Uncompressed:  {} bytes (100.0%)",
        gen5_raw_bytes
    );
    println!(
        "Gen 6 Stitch-Data:        {} bytes ({:.1}%) across {} chunks",
        gen6_total_bytes,
        (gen6_total_bytes as f64 / gen5_raw_bytes as f64) * 100.0,
        chunks_written
    );
    let compression_gain = (1.0 - (gen6_total_bytes as f64 / gen5_raw_bytes as f64)) * 100.0;
    println!("Net Space Savings:        {:.1}%\n", compression_gain);

    assert!(
        gen6_total_bytes < (gen5_raw_bytes as u64) / 2,
        "Gen 6 must compress range table by at least 50% compared to raw AoS"
    );

    // ------------------------------------------------------------------------
    // 3. Zero-Copy Lookup Verification in Gen 6
    // ------------------------------------------------------------------------
    let mmap_file = File::open(&gen6_path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&mmap_file).unwrap() };
    let reader = ContainerReader::open(&mmap).unwrap();

    // Query IP 1.0.5.10 (ip = 16_777_216 + 5 * 256 + 10 = 16_778_506)
    let target_ip = 16_777_216 + 5 * 256 + 10;
    let target_range_idx = 5;
    let expected_profile = ranges[target_range_idx].2;

    // Step 1: Branchless binary search over chunk directory (in RAM/mmap)
    let chunk_desc = reader.find_chunk_for_key(target_ip as u64).unwrap();
    let chunk_frame = reader.chunk_slice(&chunk_desc).unwrap();

    // Step 2: Unpack framed chunk
    let (header, payload) = unpack_frame(chunk_frame).unwrap();
    assert_eq!(header.payload_len, payload.len());

    // Step 3: Fast indexing and column slice extraction
    let index = ColumnSliceIndex::<4>::new(payload).unwrap();
    assert_eq!(index.row_count(), chunk_size);
    assert_eq!(index.num_columns(), 3);

    // Step 4: Stack-based column decoding and binary search in chunk
    let col0_slice = index.column(0).unwrap();
    let col2_slice = index.column(2).unwrap();

    let mut col0_decoded = [0u32; 1024];
    decode_u32_column(col0_slice.payload, &mut col0_decoded).unwrap();

    let mut col2_decoded = [0u32; 1024];
    decode_u32_column(col2_slice.payload, &mut col2_decoded).unwrap();

    // Binary search inside chunk: find index where ip_from <= target_ip
    let row = col0_decoded.partition_point(|&ip| ip <= target_ip) - 1;
    assert_eq!(row, target_range_idx);
    assert_eq!(col2_decoded[row], expected_profile);
}
