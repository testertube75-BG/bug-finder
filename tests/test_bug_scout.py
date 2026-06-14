from __future__ import annotations

import unittest

from app import detect_file_signature, normalize_url, parse_ports, response_similarity


class TestBugScout(unittest.TestCase):
    """Regression tests for public Bug Scout helper functions."""

    def test_normalize_url_http(self) -> None:
        """Add HTTPS when a URL has no scheme."""

        result = normalize_url("example.com")
        self.assertTrue(result.startswith("https://"))

    def test_normalize_url_invalid(self) -> None:
        """Reject invalid URL text."""

        with self.assertRaises(ValueError):
            normalize_url("not a url")

    def test_detect_file_signature_pdf(self) -> None:
        """Detect PDF magic bytes."""

        pdf_bytes = b"%PDF-1.4..."
        result = detect_file_signature(pdf_bytes, "")
        self.assertEqual(result, "PDF document")

    def test_response_similarity(self) -> None:
        """Identical text returns 1.0 similarity."""

        text = "hello world test"
        sim = response_similarity(text, text)
        self.assertEqual(sim, 1.0)

    def test_parse_ports_valid(self) -> None:
        """Parse comma-separated ports and ranges."""

        ports = parse_ports("80,443,8000-8010")
        self.assertIn(80, ports)
        self.assertIn(8005, ports)

    def test_parse_ports_limit(self) -> None:
        """Reject scans over 100 ports."""

        with self.assertRaises(ValueError):
            parse_ports("1-300")


if __name__ == "__main__":
    unittest.main()
