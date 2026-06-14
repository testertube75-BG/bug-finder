from __future__ import annotations

import unittest

from app import Finding, MLDetector, ResponseAnalysis, build_arg_parser, build_update_plan, findings_to_csv, normalize_url, parse_ports, report_to_html, ScanConfig, TargetError
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

    def test_ml_detector_scores_secret_response(self) -> None:
        """MLDetector raises score for secret-like responses."""

        response = ResponseAnalysis(url="https://example.com", file_signature="dotenv/config file", keyword_matches=["secret"])
        self.assertGreaterEqual(MLDetector.score_response(response), 75)

    def test_findings_to_csv_exports_rows(self) -> None:
        """Findings can be exported to CSV."""

        csv_text = findings_to_csv([{"title": "Title", "severity": "info", "url": "https://example.com", "category": "test", "detail": "detail"}])
        self.assertIn("severity,title,url", csv_text)
        self.assertIn("Title", csv_text)

    def test_report_to_html_exports_document(self) -> None:
        """Reports can be exported as standalone HTML."""

        html_text = report_to_html({"target": "https://example.com", "findings": [{"severity": "info", "title": "T", "url": "u", "detail": "d"}]})
        self.assertIn("<!doctype html>", html_text)
        self.assertIn("https://example.com", html_text)

    def test_cli_parser_accepts_terminal_mode(self) -> None:
        """CLI parser supports terminal-only scan arguments."""

        args = build_arg_parser().parse_args(["--target", "example.com", "--output", "json"])
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.output, "json")

    def test_cli_parser_accepts_update_mode(self) -> None:
        """CLI parser supports update checks."""

        args = build_arg_parser().parse_args(["--update"])
        self.assertTrue(args.update)

    def test_build_update_plan_detects_changed_files(self) -> None:
        """Updater compares local and remote file contents by hash."""

        plan = build_update_plan({"app.py": "remote"}, {"app.py": "local"})
        self.assertEqual(plan[0]["path"], "app.py")
        self.assertNotEqual(plan[0]["local_sha256"], plan[0]["remote_sha256"])


if __name__ == "__main__":
    unittest.main()
