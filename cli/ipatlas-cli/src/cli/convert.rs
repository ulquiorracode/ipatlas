use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use ipatlas_core::{
    HeaderVariant, IpAtlasReader, StorageLayout, HEADER_SIZE_V4, HEADER_SIZE_V5,
    RECORD_SIZE_V4_COMPACT, RECORD_SIZE_V4_STANDARD, VERSION_V4_COMPACT_AOS,
    VERSION_V4_COMPACT_SOA, VERSION_V4_STANDARD_AOS, VERSION_V4_STANDARD_SOA,
    VERSION_V5_COMPACT_AOS, VERSION_V5_COMPACT_SOA, VERSION_V5_STANDARD_AOS,
    VERSION_V5_STANDARD_SOA,
};
use zerocopy::IntoBytes;

use crate::cli::args::{format_num, ConvertArgs};

pub fn run_convert(args: ConvertArgs) -> anyhow::Result<()> {
    if !args.input.exists() {
        anyhow::bail!("Input database not found: {:?}", args.input);
    }

    println!("Opening input database: {:?}...", args.input);
    let reader = IpAtlasReader::open(&args.input)?;

    let target_layout = match args.layout.to_lowercase().as_str() {
        "soa" | "structure-of-arrays" => StorageLayout::Soa,
        "aos" | "array-of-structures" => StorageLayout::Aos,
        other => anyhow::bail!("Unknown layout: '{}'. Available: aos, soa", other),
    };

    if reader.layout() == target_layout {
        println!(
            "Database is already in {:?} layout. Copying directly.",
            target_layout
        );
        std::fs::copy(&args.input, &args.output)?;
        return Ok(());
    }

    println!(
        "Converting from {:?} to {:?} (Total IPv4 records: {})...",
        reader.layout(),
        target_layout,
        format_num(reader.len_v4())
    );

    let t0 = Instant::now();
    let out_file = File::create(&args.output)?;
    let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, out_file);

    let raw_mmap = reader.raw_bytes();

    match reader.header() {
        HeaderVariant::V4(mut h) => {
            let total = h.total_records as usize;
            let is_compact = reader.is_compact();

            // Update header version
            h.version = match (is_compact, target_layout) {
                (false, StorageLayout::Aos) => VERSION_V4_STANDARD_AOS,
                (false, StorageLayout::Soa) => VERSION_V4_STANDARD_SOA,
                (true, StorageLayout::Aos) => VERSION_V4_COMPACT_AOS,
                (true, StorageLayout::Soa) => VERSION_V4_COMPACT_SOA,
            };

            writer.write_all(h.as_bytes())?;

            if target_layout == StorageLayout::Soa {
                // Convert AoS -> SoA
                if is_compact {
                    let ranges = reader.ranges_compact();
                    for r in ranges {
                        writer.write_all(&r.ip_from.to_le_bytes())?;
                    }
                    for r in ranges {
                        writer.write_all(&r.count.to_le_bytes())?;
                    }
                    for r in ranges {
                        writer.write_all(&r.profile_id.to_le_bytes())?;
                    }
                } else {
                    let ranges = reader.ranges();
                    for r in ranges {
                        writer.write_all(&r.ip_from.to_le_bytes())?;
                    }
                    for r in ranges {
                        writer.write_all(&r.ip_to.to_le_bytes())?;
                    }
                    for r in ranges {
                        writer.write_all(&r.profile_id.to_le_bytes())?;
                    }
                }
            } else {
                // Convert SoA -> AoS
                let ip_froms = reader.soa_ip_froms_v4();
                if is_compact {
                    let counts = reader.soa_counts_v4();
                    let profs = reader.soa_profile_ids_compact_v4();
                    for i in 0..total {
                        writer.write_all(&ip_froms[i].to_le_bytes())?;
                        writer.write_all(&counts[i].to_le_bytes())?;
                        writer.write_all(&profs[i].to_le_bytes())?;
                    }
                } else {
                    let tos = reader.soa_ip_tos_standard_v4();
                    let profs = reader.soa_profile_ids_standard_v4();
                    for i in 0..total {
                        writer.write_all(&ip_froms[i].to_le_bytes())?;
                        writer.write_all(&tos[i].to_le_bytes())?;
                        writer.write_all(&profs[i].to_le_bytes())?;
                    }
                }
            }

            // Copy remainder of the file (profiles + string tables) directly
            let v4_bytes = if is_compact {
                total * (RECORD_SIZE_V4_COMPACT as usize)
            } else {
                total * (RECORD_SIZE_V4_STANDARD as usize)
            };
            let remainder_start = HEADER_SIZE_V4 + v4_bytes;
            if remainder_start < raw_mmap.len() {
                writer.write_all(&raw_mmap[remainder_start..])?;
            }
        }
        HeaderVariant::V5(mut h) => {
            let total_v4 = h.total_records_v4 as usize;
            let is_compact = reader.is_compact();

            h.version = match (is_compact, target_layout) {
                (false, StorageLayout::Aos) => VERSION_V5_STANDARD_AOS,
                (false, StorageLayout::Soa) => VERSION_V5_STANDARD_SOA,
                (true, StorageLayout::Aos) => VERSION_V5_COMPACT_AOS,
                (true, StorageLayout::Soa) => VERSION_V5_COMPACT_SOA,
            };

            writer.write_all(h.as_bytes())?;

            if target_layout == StorageLayout::Soa {
                if is_compact {
                    let ranges = reader.ranges_compact();
                    for r in ranges {
                        writer.write_all(&r.ip_from.to_le_bytes())?;
                    }
                    for r in ranges {
                        writer.write_all(&r.count.to_le_bytes())?;
                    }
                    for r in ranges {
                        writer.write_all(&r.profile_id.to_le_bytes())?;
                    }
                } else {
                    let ranges = reader.ranges();
                    for r in ranges {
                        writer.write_all(&r.ip_from.to_le_bytes())?;
                    }
                    for r in ranges {
                        writer.write_all(&r.ip_to.to_le_bytes())?;
                    }
                    for r in ranges {
                        writer.write_all(&r.profile_id.to_le_bytes())?;
                    }
                }
            } else {
                let ip_froms = reader.soa_ip_froms_v4();
                if is_compact {
                    let counts = reader.soa_counts_v4();
                    let profs = reader.soa_profile_ids_compact_v4();
                    for i in 0..total_v4 {
                        writer.write_all(&ip_froms[i].to_le_bytes())?;
                        writer.write_all(&counts[i].to_le_bytes())?;
                        writer.write_all(&profs[i].to_le_bytes())?;
                    }
                } else {
                    let tos = reader.soa_ip_tos_standard_v4();
                    let profs = reader.soa_profile_ids_standard_v4();
                    for i in 0..total_v4 {
                        writer.write_all(&ip_froms[i].to_le_bytes())?;
                        writer.write_all(&tos[i].to_le_bytes())?;
                        writer.write_all(&profs[i].to_le_bytes())?;
                    }
                }
            }

            let v4_bytes = if is_compact {
                total_v4 * (RECORD_SIZE_V4_COMPACT as usize)
            } else {
                total_v4 * (RECORD_SIZE_V4_STANDARD as usize)
            };
            let remainder_start = HEADER_SIZE_V5 + v4_bytes;
            if remainder_start < raw_mmap.len() {
                writer.write_all(&raw_mmap[remainder_start..])?;
            }
        }
    }

    writer.flush()?;
    println!(
        "Successfully converted in {:.3}s -> {:?}",
        t0.elapsed().as_secs_f64(),
        args.output
    );

    Ok(())
}
