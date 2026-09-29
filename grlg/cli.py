"""
GRLG Command-Line Interface.
"""

import argparse
import sys
import time
import os
from .compiler import compile_database
from .reader import GrlgReader

def main():
    parser = argparse.ArgumentParser(
        prog="grlg",
        description="GRLG: Ultra-fast Zero-Copy Binary GeoIP & Proxy Threat Database Tool"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # compile
    p_comp = subparsers.add_parser("compile", help="Compile CSV dataset(s) into GRLG binary and .gz")
    p_comp.add_argument("--mode", choices=["full", "proxy", "geo"], default="full", help="Compilation mode")
    p_comp.add_argument("--db5", help="Path to IP2LOCATION-LITE-DB5.CSV")
    p_comp.add_argument("--px10", help="Path to IP2PROXY-LITE-PX10.CSV")
    p_comp.add_argument("--out", "-o", required=True, help="Output binary path (.bin)")

    # lookup
    p_look = subparsers.add_parser("lookup", help="Query an IP address in GRLG database")
    p_look.add_argument("database", help="Path to .bin database")
    p_look.add_argument("ip", help="IPv4 address to look up")

    # info
    p_info = subparsers.add_parser("info", help="Inspect GRLG database header and stats")
    p_info.add_argument("database", help="Path to .bin database")

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Measure lookup throughput and latency")
    p_bench.add_argument("database", help="Path to .bin database")
    p_bench.add_argument("-n", "--count", type=int, default=100000, help="Number of lookups")

    args = parser.parse_args()

    if args.command == "compile":
        try:
            compile_database(
                mode=args.mode,
                output_path=args.out,
                db5_path=args.db5,
                px10_path=args.px10,
                progress_callback=print
            )
        except Exception as e:
            sys.exit(f"Error compiling database: {e}")

    elif args.command == "lookup":
        if not os.path.exists(args.database):
            sys.exit(f"Database not found: {args.database}")
        with GrlgReader(args.database) as reader:
            t0 = time.perf_counter()
            rec = reader.lookup(args.ip)
            dt_us = (time.perf_counter() - t0) * 1e6
            if rec:
                print(f"IP:          {rec.ip}")
                print(f"Range:       {rec.range}")
                print(f"Country:     {rec.country}")
                print(f"Region:      {rec.region}")
                print(f"City:        {rec.city}")
                print(f"Coordinates: {rec.latitude:.2f}, {rec.longitude:.2f}")
                print(f"ISP:         {rec.isp or 'N/A'}")
                print(f"ASN:         AS{rec.asn if rec.asn else 'N/A'}")
                print(f"Flags:       {hex(rec.flags.value)}")
                print(f"  Datacenter:  {rec.flags.is_datacenter}")
                print(f"  Proxy / VPN: {rec.flags.is_proxy}")
                print(f"  Botnet:      {rec.flags.is_botnet}")
                print(f"  Spam:        {rec.flags.is_spam}")
                print(f"  Mobile:      {rec.flags.is_mobile}")
                print(f"  Residential: {rec.flags.is_residential}")
                print(f"Lookup Time: {dt_us:.2f} µs")
            else:
                print(f"IP {args.ip} not found in database (took {dt_us:.2f} µs)")

    elif args.command == "info":
        if not os.path.exists(args.database):
            sys.exit(f"Database not found: {args.database}")
        with GrlgReader(args.database) as reader:
            mode_str = {1: "Proxy-Only", 2: "Geo-Only", 3: "Unified Full"}.get(reader.version, "Unknown")
            size_mb = os.path.getsize(args.database) / (1024 * 1024)
            print(f"Database:      {args.database}")
            print(f"Format:        GRLG Version {reader.version} ({mode_str})")
            print(f"Records:       {reader.total_records:,}")
            print(f"Record Size:   {reader.record_size} bytes")
            print(f"Indexed Cities: {len(reader._city_offsets):,}")
            print(f"Indexed Regions:{len(reader._region_offsets):,}")
            print(f"Indexed ISPs:  {len(reader._isp_offsets):,}")
            print(f"File Size:     {size_mb:.2f} MB")

    elif args.command == "benchmark":
        if not os.path.exists(args.database):
            sys.exit(f"Database not found: {args.database}")
        import random
        # Generate random IPs
        ips = [f"{random.randint(1,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(args.count)]
        print(f"Benchmarking {args.count:,} lookups against {args.database}...")
        with GrlgReader(args.database) as reader:
            t0 = time.perf_counter()
            found = 0
            for ip in ips:
                if reader.lookup(ip) is not None:
                    found += 1
            total_time = time.perf_counter() - t0
            qps = args.count / total_time
            lat_ns = (total_time / args.count) * 1e9
            print(f"Completed in {total_time:.3f}s")
            print(f"Throughput: {qps:,.0f} queries/sec")
            print(f"Average Latency: {lat_ns:.0f} ns/query ({lat_ns/1000:.2f} µs)")
            print(f"Hit rate: {found}/{args.count} ({found/args.count*100:.1f}%)")

if __name__ == "__main__":
    main()
