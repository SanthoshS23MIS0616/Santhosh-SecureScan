import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner import extract_versions, normalize_target, parse_ports


class ScannerUnitTests(unittest.TestCase):
    def test_normalize_target_url(self):
        target = normalize_target("https://example.com:8443/path")
        self.assertEqual(target["host"], "example.com")
        self.assertEqual(target["scheme"], "https")
        self.assertEqual(target["requested_port"], 8443)

    def test_parse_custom_ports(self):
        ports = parse_ports(custom_ports="80,443,8000-8002")
        self.assertEqual(ports, [80, 443, 8000, 8001, 8002])

    def test_extract_versions(self):
        versions = extract_versions("Apache/2.2.31 PHP/7.4.2")
        products = {item["product"]: item for item in versions}
        self.assertTrue(products["Apache"]["outdated_hint"])
        self.assertTrue(products["PHP"]["outdated_hint"])


if __name__ == "__main__":
    unittest.main()

