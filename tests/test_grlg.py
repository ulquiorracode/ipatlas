import tempfile
import os
import socket
import struct
import unittest
from grlg.compiler import compile_database
from grlg.reader import GrlgReader

def ip2int(ip_str: str) -> int:
    return struct.unpack('!I', socket.inet_aton(ip_str))[0]

class TestGrlg(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = self.temp_dir.name
        
        self.db5_path = os.path.join(self.tmp_path, "test_db5.csv")
        self.px10_path = os.path.join(self.tmp_path, "test_px10.csv")
        
        # DB5: ip_from, ip_to, cc, country_name, region, city, lat, lon
        db5_lines = [
            f'{ip2int("1.0.0.0")},{ip2int("1.0.15.255")},US,United States,California,Los Angeles,34.05,-118.24\n',
            f'{ip2int("1.0.16.0")},{ip2int("1.0.31.255")},JP,Japan,Tokyo,Tokyo,35.68,139.69\n',
            f'{ip2int("1.0.32.0")},{ip2int("1.0.47.255")},RU,Russian Federation,Moskva,Moscow,55.75,37.61\n',
        ]
        with open(self.db5_path, "w", encoding="utf-8") as f:
            f.writelines(db5_lines)
            
        # PX10: ip_from, ip_to, proxy_type, cc, country_name, region, city, isp, domain, usage_type, asn, as_name, last_seen, threat
        # One proxy overlaps inside Tokyo range: 1.0.20.0 - 1.0.20.255
        px10_lines = [
            f'{ip2int("1.0.20.0")},{ip2int("1.0.20.255")},PUB,JP,Japan,Tokyo,Tokyo,DataCenter Host,dc.jp,DCH,13335,CLOUDFLARE,2026-09-01,BOTNET\n',
        ]
        with open(self.px10_path, "w", encoding="utf-8") as f:
            f.writelines(px10_lines)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_compile_and_lookup_full(self):
        out_bin = os.path.join(self.tmp_path, "unified.bin")
        stats = compile_database(
            mode="full",
            output_path=out_bin,
            db5_path=self.db5_path,
            px10_path=self.px10_path,
        )
        
        self.assertEqual(stats["records"], 5)
        self.assertEqual(stats["profiles"], 4)
        self.assertTrue(os.path.exists(out_bin))
        self.assertTrue(os.path.exists(out_bin + ".gz"))
        if stats["zst_size"]:
            self.assertTrue(os.path.exists(out_bin + ".zst"))
        
        with GrlgReader(out_bin) as reader:
            # 1. Clean residential US
            res_us = reader.lookup("1.0.5.10")
            self.assertIsNotNone(res_us)
            self.assertEqual(res_us.country, "US")
            self.assertEqual(res_us.city, "Los Angeles")
            self.assertEqual(res_us.region, "California")
            self.assertAlmostEqual(res_us.latitude, 34.05, places=2)
            self.assertFalse(res_us.flags.is_proxy)
            self.assertFalse(res_us.flags.is_datacenter)
            
            # 2. Clean Tokyo
            res_jp = reader.lookup("1.0.18.1")
            self.assertIsNotNone(res_jp)
            self.assertEqual(res_jp.country, "JP")
            self.assertEqual(res_jp.city, "Tokyo")
            self.assertFalse(res_jp.flags.is_proxy)
            
            # 3. Proxy in Tokyo (DCH + BOTNET)
            res_proxy = reader.lookup("1.0.20.55")
            self.assertIsNotNone(res_proxy)
            self.assertEqual(res_proxy.country, "JP")
            self.assertEqual(res_proxy.city, "Tokyo")
            self.assertEqual(res_proxy.isp, "DataCenter Host")
            self.assertEqual(res_proxy.asn, 13335)
            self.assertTrue(res_proxy.flags.is_proxy)
            self.assertTrue(res_proxy.flags.is_datacenter)
            self.assertTrue(res_proxy.flags.is_botnet)
            
            # 4. Clean Moscow
            res_ru = reader.lookup("1.0.40.1")
            self.assertIsNotNone(res_ru)
            self.assertEqual(res_ru.country, "RU")
            self.assertEqual(res_ru.city, "Moscow")
            self.assertFalse(res_ru.flags.is_proxy)

            # 5. IP outside ranges
            self.assertIsNone(reader.lookup("2.2.2.2"))

    def test_compile_geo_only(self):
        out_bin = os.path.join(self.tmp_path, "geo_only.bin")
        stats = compile_database(
            mode="geo",
            output_path=out_bin,
            db5_path=self.db5_path,
        )
        self.assertEqual(stats["records"], 3)
        with GrlgReader(out_bin) as reader:
            rec = reader.lookup("1.0.40.1")
            self.assertIsNotNone(rec)
            self.assertEqual(rec.country, "RU")
            self.assertEqual(rec.city, "Moscow")

    def test_compile_proxy_only(self):
        out_bin = os.path.join(self.tmp_path, "proxy_only.bin")
        stats = compile_database(
            mode="proxy",
            output_path=out_bin,
            px10_path=self.px10_path,
        )
        self.assertEqual(stats["records"], 1)
        with GrlgReader(out_bin) as reader:
            rec = reader.lookup("1.0.20.100")
            self.assertIsNotNone(rec)
            self.assertEqual(rec.isp, "DataCenter Host")
            self.assertTrue(rec.flags.is_proxy)
            self.assertTrue(rec.flags.is_datacenter)

if __name__ == "__main__":
    unittest.main()
