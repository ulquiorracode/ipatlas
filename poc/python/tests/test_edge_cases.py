"""
Edge case and robustness tests for IPAtlas binary format V4 and reader.
"""

import os
import socket
import struct
import tempfile
import unittest
from ipatlas.compiler import compile_database
from ipatlas.reader import IpAtlasReader


def ip2int(ip_str: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = self.temp_dir.name
        self.db_path = os.path.join(self.tmp_path, "edge_db.csv")
        self.px_path = os.path.join(self.tmp_path, "edge_px.csv")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_extreme_ipv4_boundaries(self):
        """Tests lookup at the extreme ends of IPv4 space: 0.0.0.0 and 255.255.255.255."""
        db_lines = [
            f"{ip2int('0.0.0.0')},{ip2int('0.0.0.255')},ZZ,Zero Net,Zero,Zero,0.0,0.0\n",
            f"{ip2int('10.0.0.100')},{ip2int('10.0.0.200')},US,United States,CA,LA,34.0,-118.0\n",
            f"{ip2int('255.255.255.0')},{ip2int('255.255.255.255')},BC,Broadcast Net,End,End,90.0,0.0\n",
        ]
        with open(self.db_path, "w", encoding="utf-8") as f:
            f.writelines(db_lines)

        out_bin = os.path.join(self.tmp_path, "boundary.bin")
        compile_database(
            mode="geo",
            output_path=out_bin,
            db_path=self.db_path,
        )

        with IpAtlasReader(out_bin) as reader:
            # 0.0.0.0 exact start
            r0 = reader.lookup("0.0.0.0")
            self.assertIsNotNone(r0)
            self.assertEqual(r0.country, "ZZ")

            # 0.0.0.255 exact end of interval
            r0_end = reader.lookup("0.0.0.255")
            self.assertIsNotNone(r0_end)
            self.assertEqual(r0_end.country, "ZZ")

            # 0.0.1.0 boundary gap outside
            self.assertIsNone(reader.lookup("0.0.1.0"))

            # Middle interval exact boundaries
            self.assertIsNone(reader.lookup("10.0.0.99"))
            self.assertIsNotNone(reader.lookup("10.0.0.100"))
            self.assertIsNotNone(reader.lookup("10.0.0.200"))
            self.assertIsNone(reader.lookup("10.0.0.201"))

            # 255.255.255.255 exact end of 32-bit integer range
            self.assertIsNone(reader.lookup("255.255.254.255"))
            self.assertIsNotNone(reader.lookup("255.255.255.0"))
            r_last = reader.lookup("255.255.255.255")
            self.assertIsNotNone(r_last)
            self.assertEqual(r_last.country, "BC")

    def test_corrupted_header_handling(self):
        """Tests that reader safely raises ValueError on corrupted or truncated binary files."""
        corrupted_bin = os.path.join(self.tmp_path, "corrupted.bin")

        # Empty file
        with open(corrupted_bin, "wb") as f:
            f.write(b"")
        with self.assertRaises(ValueError):
            with IpAtlasReader(corrupted_bin):
                pass

        # Invalid magic header
        with open(corrupted_bin, "wb") as f:
            f.write(b"BADMAGIC" + b"\x00" * 40)
        with self.assertRaises(ValueError):
            with IpAtlasReader(corrupted_bin):
                pass

        # Valid magic, but truncated header (< 40 bytes)
        with open(corrupted_bin, "wb") as f:
            f.write(b"ATLS\x04\x00\x00\x00")
        with self.assertRaises(ValueError):
            with IpAtlasReader(corrupted_bin):
                pass

    def test_empty_database_lookup(self):
        """Tests compiling an empty file results in graceful 0-record binary."""
        empty_db = os.path.join(self.tmp_path, "empty.csv")
        with open(empty_db, "w", encoding="utf-8") as f:
            f.write("")

        out_bin = os.path.join(self.tmp_path, "empty.bin")
        stats = compile_database(
            mode="geo",
            output_path=out_bin,
            db_path=empty_db,
        )
        self.assertEqual(stats["records"], 0)

        with IpAtlasReader(out_bin) as reader:
            self.assertEqual(len(reader), 0)
            self.assertIsNone(reader.lookup("1.1.1.1"))
            self.assertIsNone(reader.lookup("0.0.0.0"))


if __name__ == "__main__":
    unittest.main()
