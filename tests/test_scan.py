from __future__ import annotations

import unittest

from app import ScanConfig, TargetError, normalize_url, parse_ports
from rate_limiter import RateLimiter


class TestScanConfig(unittest.TestCase):
    """Tests for scan configuration, URL validation, ports, and rate limiting."""

    def test_normalize_url_adds_scheme(self) -> None:
        """Missing URL schemes default to HTTPS."""

        result = normalize_url("example.com")
        self.assertTrue(result.startswith("https://"))

    def test_invalid_url_raises_error(self) -> None:
        """URLs with spaces raise the custom target error."""

        with self.assertRaises(TargetError):
            normalize_url("invalid url with spaces")

    def test_parse_ports_common(self) -> None:
        """The common preset includes HTTP and HTTPS."""

        result = parse_ports("common")
        self.assertIn(80, result)
        self.assertIn(443, result)

    def test_parse_ports_range(self) -> None:
        """Port ranges expand inclusively."""

        result = parse_ports("8000-8010")
        self.assertEqual(len(result), 11)
        self.assertIn(8005, result)

    def test_scan_config_from_values(self) -> None:
        """ScanConfig.from_values normalizes target and preserves bounded values."""

        config = ScanConfig.from_values("example.com", 8, 8, True, "", "")
        self.assertEqual(config.target, "https://example.com")
        self.assertEqual(config.max_pages, 8)

    def test_rate_limiter_blocks_after_limit(self) -> None:
        """RateLimiter rejects a client after the configured request count."""

        limiter = RateLimiter(max_requests=2, window=60)
        self.assertTrue(limiter.is_allowed("127.0.0.1"))
        self.assertTrue(limiter.is_allowed("127.0.0.1"))
        self.assertFalse(limiter.is_allowed("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
