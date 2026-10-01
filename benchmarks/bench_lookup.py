"""
IPAtlas Performance Benchmarks: Lookup Latency & Throughput.
"""

import os
import random
import socket
import struct
import tempfile
import time
from typing import List, Tuple
from ipatlas.compiler import compile_database
from ipatlas.reader import IpAtlasReader


def ip2int(ip_str: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def int2ip(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def generate_synthetic_data(num_records: int, db_path: str, px_path: str) -> List[Tuple[int, int]]:
    """Generates synthetic non-overlapping intervals for benchmarking."""
    print(f"Generating {num_records} synthetic records...")
    ranges = []
    curr = 16777216  # 1.0.0.0

    db_lines = []
    px_lines = []
    countries = ["US", "DE", "FR", "GB", "JP", "RU", "SG", "NL", "CA", "AU"]
    cities = ["New York", "Berlin", "Paris", "London", "Tokyo", "Moscow", "Singapore", "Amsterdam", "Toronto", "Sydney"]

    for i in range(num_records):
        step = random.randint(256, 4096)
        ip_from = curr
        ip_to = curr + step - 1
        # In real data, contiguous blocks belong to the same country but different cities/subnets
        curr = ip_to + 1
        ranges.append((ip_from, ip_to))

        country_idx = (i // 5) % len(countries) # 5 contiguous blocks per country
        cc = countries[country_idx]
        city = f"City_{i % 50}"
        region = f"Region_{country_idx}"

        db_lines.append(f"{ip_from},{ip_to},{cc},Country_{cc},{region},{city},10.0,20.0\n")
        if i % 4 == 0:  # 25% proxies
            px_lines.append(f"{ip_from},{ip_to},VPN,{cc},Country_{cc},{region},{city},ISP_{i%20},host.com,DCH,1234,AS_NAME,2026-01-01,VPN\n")

    with open(db_path, "w", encoding="utf-8") as f:
        f.writelines(db_lines)
    with open(px_path, "w", encoding="utf-8") as f:
        f.writelines(px_lines)

    return ranges


def run_benchmark(num_records: int = 100_000, num_lookups: int = 100_000):
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "synth_db.csv")
        px_path = os.path.join(tmp_dir, "synth_px.csv")
        bin_path = os.path.join(tmp_dir, "synth.bin")

        ranges = generate_synthetic_data(num_records, db_path, px_path)

        print("\nCompiling database...")
        t0 = time.perf_counter()
        stats = compile_database("full", bin_path, db_path=db_path, px_path=px_path)
        comp_time = time.perf_counter() - t0
        bin_mb = os.path.getsize(bin_path) / (1024 * 1024)
        print(f"Compilation finished in {comp_time:.2f}s: {stats['records']} intervals, {stats['profiles']} profiles, {bin_mb:.2f} MB")

        # Prepare lookup query sets
        # 1. Guaranteed Hits (random points inside generated ranges)
        hit_ips = []
        for _ in range(num_lookups):
            r = random.choice(ranges)
            hit_ips.append(int2ip(random.randint(r[0], r[1])))

        # 2. Random Global IPv4 (mixture of hits & misses)
        random_ips = [int2ip(random.randint(1, 0xFFFFFFFF)) for _ in range(num_lookups)]

        with IpAtlasReader(bin_path) as reader:
            print(f"\n=======================================================")
            print(f" Running Benchmark: {num_lookups:,} lookups over {len(reader):,} intervals")
            print(f"=======================================================")

            # Test 1: Hit queries
            t_start = time.perf_counter_ns()
            hits_found = 0
            for ip in hit_ips:
                rec = reader.lookup(ip)
                if rec is not None:
                    hits_found += 1
            t_end = time.perf_counter_ns()

            total_ns = t_end - t_start
            avg_ns = total_ns / num_lookups
            qps = (num_lookups / total_ns) * 1_000_000_000
            print(f"\n[Test 1] In-Database Lookups (Hits):")
            print(f"  Total time:       {total_ns / 1_000_000:.2f} ms")
            print(f"  Average latency:  {avg_ns:.2f} ns ({avg_ns / 1000.0:.3f} \u00b5s)")
            print(f"  Throughput:       {qps:,.0f} queries/sec")
            print(f"  Hit rate:         {(hits_found / num_lookups) * 100:.1f}%")

            # Test 2: Random queries
            t_start = time.perf_counter_ns()
            rand_hits = 0
            for ip in random_ips:
                rec = reader.lookup(ip)
                if rec is not None:
                    rand_hits += 1
            t_end = time.perf_counter_ns()

            total_ns = t_end - t_start
            avg_ns = total_ns / num_lookups
            qps = (num_lookups / total_ns) * 1_000_000_000
            print(f"\n[Test 2] Random Uniform IPv4 Lookups (Hits + Misses):")
            print(f"  Total time:       {total_ns / 1_000_000:.2f} ms")
            print(f"  Average latency:  {avg_ns:.2f} ns ({avg_ns / 1000.0:.3f} \u00b5s)")
            print(f"  Throughput:       {qps:,.0f} queries/sec")
            print(f"  Hit rate:         {(rand_hits / num_lookups) * 100:.2f}%")
            print(f"=======================================================\n")


if __name__ == "__main__":
    run_benchmark(num_records=50_000, num_lookups=50_000)
