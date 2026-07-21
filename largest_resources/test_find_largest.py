import unittest

from find_largest import normalize_url


class NormalizeTests(unittest.TestCase):
    def test_normalizes_for_bfs_deduplication(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.TEST:443/a/?z=2&a=1#fragment"),
            "https://example.test/a?a=1&z=2",
        )

    def test_rejects_non_http_scheme(self):
        self.assertIsNone(normalize_url("javascript:alert(1)"))


if __name__ == "__main__":
    unittest.main()
