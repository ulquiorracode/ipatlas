use std::time::Instant;

use ipatlas::{
    FeatureMask, IpAtlasPipelineExt, IpAtlasReader, LookupContext, LookupIntent,
    OptimizationConfig, Preset, RecordFamily, StorageLayout, RECORD_SIZE_V4_COMPACT,
    RECORD_SIZE_V4_STANDARD, RECORD_SIZE_V6,
};

use crate::cli::args::{format_num, CompileArgs, InfoArgs, LookupArgs};

pub fn run_compile(args: CompileArgs) -> anyhow::Result<()> {
    let feature_mask = if let Some(preset_name) = &args.preset {
        match Preset::from_str_name(preset_name) {
            Some(p) => p.feature_mask(),
            None => anyhow::bail!(
                "Unknown preset: '{}'. Available: full, city, firewall, country, threats",
                preset_name
            ),
        }
    } else if let Some(feat_str) = &args.features {
        FeatureMask::parse_csv(feat_str).map_err(|e| anyhow::anyhow!(e))?
    } else {
        match args.mode.to_lowercase().as_str() {
            "proxy" => FeatureMask(
                FeatureMask::COUNTRY
                    | FeatureMask::CITY
                    | FeatureMask::ISP
                    | FeatureMask::ASN
                    | FeatureMask::THREATS,
            ),
            "geo" => FeatureMask(
                FeatureMask::COUNTRY
                    | FeatureMask::REGION
                    | FeatureMask::CITY
                    | FeatureMask::COORDS,
            ),
            _ => FeatureMask::default(),
        }
    };

    let mut opt_config = OptimizationConfig::default();
    match args.family.to_lowercase().as_str() {
        "compact" | "v4.1" => {
            opt_config.compact_ranges = true;
            opt_config.family = RecordFamily::Compact;
        }
        "standard" | "v4" => {
            opt_config.compact_ranges = false;
            opt_config.family = RecordFamily::Standard;
        }
        other => anyhow::bail!("Unknown family: '{}'. Available: compact, standard", other),
    }

    match args.layout.to_lowercase().as_str() {
        "soa" | "structure-of-arrays" => opt_config.layout = StorageLayout::Soa,
        "aos" | "array-of-structures" => opt_config.layout = StorageLayout::Aos,
        other => anyhow::bail!("Unknown layout: '{}'. Available: aos, soa", other),
    }

    if args.embedded_zstd {
        opt_config.embedded_zstd = true;
    }

    for opt_arg in &args.optimization {
        opt_config
            .parse_arg(opt_arg)
            .map_err(|e| anyhow::anyhow!(e))?;
    }

    let mut geo_v4 = args.geo.as_deref();
    let mut geo_v6 = args.geo_v6.as_deref();
    let mut proxy_v4 = args.proxy.as_deref();
    let mut proxy_v6 = args.proxy_v6.as_deref();

    if geo_v6.is_none() {
        if let Some(p) = geo_v4 {
            if p.to_string_lossy().to_uppercase().contains("IPV6") {
                geo_v6 = Some(p);
                geo_v4 = None;
            }
        }
    }
    if proxy_v6.is_none() {
        if let Some(p) = proxy_v4 {
            if p.to_string_lossy().to_uppercase().contains("IPV6") {
                proxy_v6 = Some(p);
                proxy_v4 = None;
            }
        }
    }

    if geo_v4.is_none() && proxy_v4.is_none() && geo_v6.is_none() && proxy_v6.is_none() {
        anyhow::bail!("Compilation requires at least one dataset input (--geo, --proxy, --geo-v6, --proxy-v6)");
    }

    let family_label = if opt_config.compact_ranges {
        "Compact (8B V4 / 36B V6)"
    } else {
        "Standard (12B V4 / 36B V6)"
    };
    let layout_label = match opt_config.layout {
        StorageLayout::Aos => "AoS (Array of Structures)",
        StorageLayout::Soa => "SoA (Structure of Arrays)",
    };

    println!("Starting IPAtlas Database Compilation:");
    println!("  Output Target: {:?}", args.out);
    println!("  Mode:          {}", args.mode);
    println!("  Family:        {}", family_label);
    println!("  Layout:        {}", layout_label);
    println!(
        "  Optimization:  coalesce={}, lossy_coords={}, norm_strings={}",
        opt_config.coalesce, opt_config.lossy_coords, opt_config.normalize_strings
    );
    println!(
        "  Embedded Zstd: {}",
        if opt_config.embedded_zstd {
            "Enabled (Ultra-compact zstd-19 frame)"
        } else {
            "Disabled (Raw zero-copy binary)"
        }
    );
    if let Some(p) = geo_v4 {
        println!("  IPv4 Geo:      {:?}", p);
    }
    if let Some(p) = proxy_v4 {
        println!("  IPv4 Threat:   {:?}", p);
    }
    if let Some(p) = geo_v6 {
        println!("  IPv6 Geo:      {:?}", p);
    }
    if let Some(p) = proxy_v6 {
        println!("  IPv6 Threat:   {:?}", p);
    }

    let opts = ipatlas::CompilerOptions::new(&args.out)
        .geo(geo_v4)
        .proxy(proxy_v4)
        .geo_v6(geo_v6)
        .proxy_v6(proxy_v6)
        .features(feature_mask)
        .optimization(opt_config);

    let stats = ipatlas::compile(opts)?;

    let raw_mb = (stats.raw_size as f64) / (1024.0 * 1024.0);
    println!("\nCompilation Complete in {:.3}s!", stats.elapsed_secs);
    println!("  Total Ranges:  {}", format_num(stats.records));
    println!("    IPv4 Ranges: {}", format_num(stats.records_v4));
    println!("    IPv6 Ranges: {}", format_num(stats.records_v6));
    println!("  Unique Profiles: {}", format_num(stats.profiles));
    println!(
        "  Output File Size: {:.2} MB ({} bytes)",
        raw_mb,
        format_num(stats.raw_size)
    );
    println!("  Database CRC32: 0x{:08X}", stats.crc32);

    Ok(())
}

pub fn run_lookup(args: LookupArgs) -> anyhow::Result<()> {
    if !args.database.exists() {
        anyhow::bail!("Database file not found: {:?}", args.database);
    }

    let ip: std::net::IpAddr = args
        .ip
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid IPv4 or IPv6 address '{}': {}", args.ip, e))?;

    let reader = IpAtlasReader::open(&args.database)?;

    let mut ctx = LookupContext::new();
    let t0 = Instant::now();
    let outcome = reader.query_pipeline(&mut ctx, LookupIntent::new(ip))?;
    let dt = t0.elapsed();
    let dt_us = dt.as_secs_f64() * 1_000_000.0;

    if outcome.is_bogon {
        println!("IP:            {}", ip);
        println!("Status:        [BOGON / PRIVATE / RESERVED NETWORK]");
        println!("Short-Circuit: Monomorphic U-Cycle bypassed binary search (0 disk/mmap reads)");
        println!("Lookup Time:   {:.2} µs ({} ns)", dt_us, dt.as_nanos());
        return Ok(());
    }

    if let Some(rec) = outcome.record {
        println!("IP:          {}", rec.ip);
        println!("Type:        {}", if rec.is_v6 { "IPv6" } else { "IPv4" });
        println!("Range:       {}", rec.range_str());
        println!("Country:     {}", rec.country);
        println!(
            "Region:      {}",
            if rec.region.is_empty() {
                "N/A"
            } else {
                &rec.region
            }
        );
        println!(
            "City:        {}",
            if rec.city.is_empty() {
                "N/A"
            } else {
                &rec.city
            }
        );
        println!("Coordinates: {:.2}, {:.2}", rec.latitude, rec.longitude);
        println!(
            "ISP:         {}",
            if rec.isp.is_empty() { "N/A" } else { &rec.isp }
        );
        println!(
            "ASN:         {}",
            if rec.asn != 0 {
                format!("AS{}", rec.asn)
            } else {
                "N/A".to_string()
            }
        );
        println!("Flags:       {:#06x}", rec.flags.0);
        if rec.flags.is_proxy() {
            println!("  [PROXY DETECTED]");
            if rec.flags.is_vpn() {
                println!("  - VPN:         true");
            }
            if rec.flags.is_tor() {
                println!("  - TOR:         true");
            }
            if rec.flags.is_datacenter() {
                println!("  - DCH (DataCenter): true");
            }
            if rec.flags.is_pub() {
                println!("  - PUB (Public Proxy): true");
            }
            if rec.flags.is_web() {
                println!("  - WEB (Web Proxy):    true");
            }
            if rec.flags.is_ses() {
                println!("  - SES (Search Engine Spider): true");
            }
            if rec.flags.is_res() {
                println!("  - RES (Residential Proxy):   true");
            }
            if rec.flags.is_cpn() {
                println!("  - CPN (Consumer Privacy Net): true");
            }
            if rec.flags.is_epn() {
                println!("  - EPN (Enterprise Private Net): true");
            }
        }
        if rec.flags.is_botnet() {
            println!("  - Threat: BOTNET");
        }
        if rec.flags.is_spam() {
            println!("  - Threat: SPAM");
        }
        if rec.flags.is_scanner() {
            println!("  - Threat: PORT SCANNER");
        }
        if rec.flags.is_mobile() {
            println!("  - Network: MOBILE / 3G / 4G / 5G");
        }
        if rec.flags.is_cdn() {
            println!("  - Network: CDN");
        }

        println!("Lookup Time: {:.2} µs ({} ns)", dt_us, dt.as_nanos());
    } else {
        println!(
            "IP {} not found in database (took {:.2} µs)",
            args.ip, dt_us
        );
    }

    Ok(())
}

pub fn run_info(args: InfoArgs) -> anyhow::Result<()> {
    if !args.database.exists() {
        anyhow::bail!("Database file not found: {:?}", args.database);
    }

    let file_size = std::fs::metadata(&args.database)?.len();
    let size_mb = (file_size as f64) / (1024.0 * 1024.0);
    let reader = IpAtlasReader::open(&args.database)?;

    let is_v5 = reader.version() >= 5 || reader.version() >= 0x0500;
    let version_name = match reader.version() {
        0x0503 => "Generation V5 (Compact SoA Dual-Stack: 8B V4 / 36B V6)",
        0x0502 => "Generation V5 (Standard SoA Dual-Stack: 12B V4 / 36B V6)",
        0x0501 => "Generation V5 (Compact AoS Dual-Stack: 8B V4 / 36B V6)",
        0x0500 | 5 => "Generation V5 (Standard AoS Dual-Stack: 12B V4 / 36B V6)",
        0x0403 => "Generation V4 (Compact SoA IPv4: 8B/range)",
        0x0402 => "Generation V4 (Standard SoA IPv4: 12B/range)",
        0x0401 => "Generation V4 (Compact AoS IPv4: 8B/range)",
        0x0400 | 4 => "Generation V4 (Standard AoS IPv4: 12B/range)",
        v => Box::leak(format!("Version {:#06x}", v).into_boxed_str()),
    };

    println!("Database:       {:?}", args.database);
    println!("Format:         {}", version_name);
    println!(
        "Layout:         {}",
        match reader.layout() {
            StorageLayout::Aos => "AoS (Array of Structures)",
            StorageLayout::Soa => "SoA (Structure of Arrays)",
        }
    );
    println!(
        "Family:         {}",
        match reader.family() {
            RecordFamily::Compact => "Compact (8B V4)",
            RecordFamily::Standard => "Standard (12B V4)",
            RecordFamily::Succinct => "Succinct (Elias-Fano)",
        }
    );
    println!("Total Records:  {}", format_num(reader.len()));
    println!("  IPv4 Records: {}", format_num(reader.len_v4()));
    println!("  IPv6 Records: {}", format_num(reader.len_v6()));
    if reader.len_v4() > 0 {
        let v4_sz = if reader.is_compact() {
            RECORD_SIZE_V4_COMPACT
        } else {
            RECORD_SIZE_V4_STANDARD
        };
        println!("IPv4 Size:      {} bytes/record", v4_sz);
    }
    if is_v5 {
        println!("IPv6 Size:      {} bytes/record", RECORD_SIZE_V6);
    }
    println!("Profiles:       {}", format_num(reader.profile_count()));
    println!("Indexed Cities: {}", format_num(reader.city_count()));
    println!("Indexed Regions:{}", format_num(reader.region_count()));
    println!("Indexed ISPs:   {}", format_num(reader.isp_count()));
    println!(
        "Compression:    {}",
        if reader.is_embedded_zstd() {
            "Embedded Zstandard (zstd-19 frame, decompressed into RAM)"
        } else {
            "None (Raw Zero-Copy Memory-Mapped)"
        }
    );
    println!("File Size:      {:.2} MB", size_mb);

    if let Some(stored_crc) = reader.crc32() {
        let crc_res = reader.validate_checksum();
        match crc_res {
            Ok(()) => println!("Checksum:       OK ({:#010x})", stored_crc),
            Err(e) => println!("Checksum:       FAIL: {}", e),
        }
    } else {
        println!("Checksum:       N/A (Generation V4 does not store CRC32)");
    }

    Ok(())
}
