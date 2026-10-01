"""
IPAtlas Compression and Preset Matrix Benchmark.
Measures binary size, archive size, interval reduction and profile count across all presets.
"""

import os
import tempfile
from typing import Dict, Any
from ipatlas.compiler import compile_database
from benchmarks.bench_lookup import generate_synthetic_data


def benchmark_presets(num_records: int = 20_000):
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "matrix_db.csv")
        px_path = os.path.join(tmp_dir, "matrix_px.csv")

        generate_synthetic_data(num_records, db_path, px_path)
        csv_size = os.path.getsize(db_path) + os.path.getsize(px_path)
        csv_mb = csv_size / (1024 * 1024)

        presets = ["full", "city", "firewall", "country", "threats"]
        results = []

        print(f"\n=========================================================================================")
        print(f" Preset Benchmark Matrix (Input CSV: {csv_mb:.2f} MB across {num_records:,} raw rows)")
        print(f"=========================================================================================")
        print(f"{'Preset':<12} | {'Intervals':<10} | {'Profiles':<9} | {'Binary':<9} | {'ZSTD':<9} | {'Ratio':<7}")
        print(f"-------------|------------|-----------|-----------|-----------|--------")

        for preset in presets:
            out_bin = os.path.join(tmp_dir, f"{preset}.bin")
            stats = compile_database(
                mode="full",
                output_path=out_bin,
                db_path=db_path,
                px_path=px_path,
                preset=preset,
            )

            bin_size = os.path.getsize(out_bin)
            zst_size = os.path.getsize(out_bin + ".zst") if os.path.exists(out_bin + ".zst") else 0
            ratio = (csv_size / zst_size) if zst_size > 0 else (csv_size / bin_size)

            print(
                f"{preset:<12} | "
                f"{stats['records']:<10,d} | "
                f"{stats['profiles']:<9,d} | "
                f"{bin_size / 1024 / 1024:<6.2f} MB | "
                f"{zst_size / 1024 / 1024:<6.2f} MB | "
                f"{ratio:<6.1f}x"
            )

        print(f"=========================================================================================\n")


if __name__ == "__main__":
    benchmark_presets(20_000)
