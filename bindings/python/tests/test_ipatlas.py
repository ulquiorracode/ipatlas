import os
import unittest
from ipatlas import IpAtlasDatabase

class TestIpAtlasPython(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Locate sample database from dist/
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        cls.db_path = os.path.join(repo_root, "dist", "ipatlas_goldsrc_city.bin")
        if not os.path.exists(cls.db_path):
            raise unittest.SkipTest(f"Sample DB not found at: {cls.db_path}")

    def test_open_and_lookup_country(self):
        with IpAtlasDatabase.open(self.db_path) as db:
            country = db.lookup_country("8.8.8.8")
            self.assertIsNotNone(country)
            self.assertEqual(country, "US")

            # Check threat status
            is_threat = db.is_threat("8.8.8.8")
            self.assertIsInstance(is_threat, bool)

            # Check datacenter status
            is_dch = db.is_datacenter("8.8.8.8")
            self.assertIsInstance(is_dch, bool)

    def test_non_existent_ip(self):
        with IpAtlasDatabase.open(self.db_path) as db:
            flags = db.lookup_flags("0.0.0.0")
            # 0.0.0.0 is unassigned/bogon, flags should be None or 0
            country = db.lookup_country("0.0.0.0")
            self.assertIn(country, [None, "-", "--"])

    def test_invalid_and_ipv6_raises_value_error(self):
        with IpAtlasDatabase.open(self.db_path) as db:
            with self.assertRaises(ValueError):
                db.lookup_country("invalid-ip")
            with self.assertRaises(ValueError):
                db.lookup_country("2001:4860:4860::8888")

if __name__ == "__main__":
    unittest.main()
