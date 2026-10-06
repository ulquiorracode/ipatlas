use std::time::Instant;

use ipatlas::{IpAtlasPipelineExt, IpAtlasReader, LookupContext, LookupIntent};

use crate::cli::args::{format_num, BenchArgs};

pub fn run_bench(args: BenchArgs) -> anyhow::Result<()> {
    if !args.database.exists() {
        anyhow::bail!("Database file not found: {:?}", args.database);
    }

    println!(
        "Benchmarking {} lookups against {:?}...",
        format_num(args.count),
        args.database
    );
    let reader = IpAtlasReader::open(&args.database)?;

    if reader.is_empty() {
        anyhow::bail!("Cannot benchmark empty database");
    }

    // Generate pseudo-random IPs deterministically via Lehmer LCG
    let mut ip_seed: u32 = 0x811c9dc5;
    let mut test_ips = Vec::with_capacity(args.count);
    for _ in 0..args.count {
        ip_seed = ip_seed.wrapping_mul(1664525).wrapping_add(1013904223);
        test_ips.push(ip_seed);
    }

    let t0 = Instant::now();
    let mut hits = 0;
    for &ip in &test_ips {
        if reader.lookup_u32(ip).is_some() {
            hits += 1;
        }
    }
    let total_time = t0.elapsed();
    let total_secs = total_time.as_secs_f64();
    let qps = (args.count as f64) / total_secs;
    let avg_ns = (total_time.as_nanos() as f64) / (args.count as f64);

    println!(
        "Completed in {:.3}s (Single-Threaded Full Record)",
        total_secs
    );
    println!("Throughput:      {} queries/sec", format_num(qps as u64));
    println!(
        "Average Latency: {:.1} ns/query ({:.3} µs)",
        avg_ns,
        avg_ns / 1000.0
    );
    println!(
        "Hit Rate:        {}/{} ({:.1}%)",
        format_num(hits),
        format_num(args.count),
        (hits as f64 / args.count as f64) * 100.0
    );

    // Flags-only Fast Path Benchmark (Firewall mode: zero-allocation, no strings)
    let t_flags = Instant::now();
    let mut flags_hits = 0;
    for &ip in &test_ips {
        if reader.lookup_flags_u32(ip).is_some() {
            flags_hits += 1;
        }
    }
    let total_secs_flags = t_flags.elapsed().as_secs_f64();
    let qps_flags = (args.count as f64) / total_secs_flags;
    let avg_ns_flags = (t_flags.elapsed().as_nanos() as f64) / (args.count as f64);
    println!("\nFlags-Only Fast Path (Single-Threaded, No String Allocation):");
    println!(
        "Throughput:      {} queries/sec",
        format_num(qps_flags as u64)
    );
    println!(
        "Average Latency: {:.1} ns/query ({:.3} µs)",
        avg_ns_flags,
        avg_ns_flags / 1000.0
    );
    println!("Speedup vs Full: {:.2}x", qps_flags / qps);
    println!(
        "Hit Rate:        {}/{}",
        format_num(flags_hits),
        format_num(args.count)
    );

    // Country-only Fast Path Benchmark
    let t_country = Instant::now();
    let mut country_hits = 0;
    for &ip in &test_ips {
        if reader.lookup_country_code_u32(ip).is_some() {
            country_hits += 1;
        }
    }
    let total_secs_country = t_country.elapsed().as_secs_f64();
    let qps_country = (args.count as f64) / total_secs_country;
    let avg_ns_country = (t_country.elapsed().as_nanos() as f64) / (args.count as f64);
    println!("\nCountry Code Fast Path (Single-Threaded):");
    println!(
        "Throughput:      {} queries/sec",
        format_num(qps_country as u64)
    );
    println!(
        "Average Latency: {:.1} ns/query ({:.3} µs)",
        avg_ns_country,
        avg_ns_country / 1000.0
    );
    println!(
        "Hit Rate:        {}/{}",
        format_num(country_hits),
        format_num(args.count)
    );
    println!("Speedup vs Full: {:.2}x", qps_country / qps);

    // Multi-threaded benchmark via Rayon
    use rayon::prelude::*;
    let t_par = Instant::now();
    let _par_hits: usize = test_ips
        .par_iter()
        .map(|&ip| {
            if reader.lookup_u32(ip).is_some() {
                1
            } else {
                0
            }
        })
        .sum();
    let total_secs_par = t_par.elapsed().as_secs_f64();
    let qps_par = (args.count as f64) / total_secs_par;
    let avg_ns_par = (t_par.elapsed().as_nanos() as f64) / (args.count as f64);

    println!(
        "\nMulti-Threaded Throughput (Rayon {} threads):",
        rayon::current_num_threads()
    );
    println!(
        "Throughput:      {} queries/sec",
        format_num(qps_par as u64)
    );
    println!(
        "Throughput-Eq:   {:.1} ns/query (aggregate 1/QPS across {} threads)",
        avg_ns_par,
        rayon::current_num_threads()
    );
    println!("Throughput Gain: {:.1}x vs single-thread", qps_par / qps);

    // 3. stitch-rs Monomorphic U-Cycle Pipeline Benchmark
    let mut pipe_ctx = LookupContext::new();
    let mut pipe = reader.standard_pipeline();
    let t_pipe = Instant::now();
    for &ip_u32 in &test_ips {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip_u32));
        let _ = pipe.dispatch(&mut pipe_ctx, LookupIntent::new(ip));
    }
    let total_secs_pipe = t_pipe.elapsed().as_secs_f64();
    let qps_pipe = (args.count as f64) / total_secs_pipe;
    let avg_ns_pipe = (t_pipe.elapsed().as_nanos() as f64) / (args.count as f64);

    println!("\nstitch-rs Monomorphic U-Cycle Pipeline (Single-Threaded):");
    println!(
        "Throughput:      {} queries/sec",
        format_num(qps_pipe as u64)
    );
    println!("Average Latency: {:.1} ns/query", avg_ns_pipe);
    println!(
        "Bogon Bypasses:  {}",
        format_num(pipe_ctx.bogon_short_circuits)
    );

    Ok(())
}
