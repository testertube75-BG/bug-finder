from __future__ import annotations

import unittest

from app import Finding, MLDetector, PageResult, ResponseAnalysis, build_arg_parser, build_reflected_xss_probe_urls, build_update_plan, check_client_side_defenses, check_xss_indicators, detect_dom_xss_sinks, filter_report_for_scan_type, findings_to_csv, infer_service_version, normalize_url, parse_ports, report_to_html, service_hint, ScanConfig, TargetError
from rate_limiter import RateLimiter


class TestScanConfig(unittest.TestCase):
    """Tests for scan configuration, URL validation, ports, and rate limiting."""

    def test_normalize_url_adds_scheme(self) -> None:
        """Missing URL schemes default to HTTPS."""

        result = normalize_url("example.com")
        self.assertTrue(result.startswith("https://"))

    def test_normalize_url_accepts_ip_target(self) -> None:
        """IP addresses are valid scan targets."""

        self.assertEqual(normalize_url("203.0.113.5"), "https://203.0.113.5")

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

    def test_nmap_style_service_hints(self) -> None:
        """Common ports return nmap-style service hints."""

        self.assertEqual(service_hint(22), "SSH")
        self.assertEqual(service_hint(9200), "Elasticsearch")

    def test_infer_service_version_from_http_banner(self) -> None:
        """HTTP server banners produce a version guess."""

        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n"
        self.assertEqual(infer_service_version(80, banner), "nginx/1.25")

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

        html_text = report_to_html({"target": "https://example.com", "findings": [{"severity": "info", "title": "T", "url": "u", "detail": "d", "poc": "proof"}]})
        self.assertIn("<!doctype html>", html_text)
        self.assertIn("https://example.com", html_text)
        self.assertIn("proof", html_text)

    def test_dom_xss_sink_detection(self) -> None:
        """DOM XSS sink/source patterns are detected."""

        sinks = detect_dom_xss_sinks("const x = location.hash; el.innerHTML = x;")
        self.assertIn("location hash/source", sinks)
        self.assertIn("innerHTML", sinks)

    def test_check_xss_indicators_adds_dom_finding(self) -> None:
        """DOM XSS indicators create a finding with PoC."""

        findings: list[Finding] = []
        check_xss_indicators(PageResult("https://example.com"), "const x = location.hash; el.innerHTML = x;", findings)
        self.assertEqual(findings[0].category, "xss-dom")
        self.assertTrue(findings[0].poc)

    def test_reflected_xss_probe_url_builder(self) -> None:
        """Query parameters produce reflected-XSS probe URLs."""

        probes = build_reflected_xss_probe_urls(PageResult("https://example.com/search?q=test"), "custom-payload")
        self.assertIn("custom-payload", probes[0])

    def test_weak_csp_detection_adds_poc(self) -> None:
        """Weak CSP headers produce CSD findings with PoC."""

        page = PageResult("https://example.com", headers={"content-security-policy": "script-src 'unsafe-inline'"})
        findings: list[Finding] = []
        check_client_side_defenses(page, findings)
        self.assertEqual(findings[0].category, "csd")
        self.assertIn("Content-Security-Policy", findings[0].poc)

    def test_cli_parser_accepts_terminal_mode(self) -> None:
        """CLI parser supports terminal-only scan arguments."""

        args = build_arg_parser().parse_args(["--target", "example.com", "--output", "json", "--xss-payload", "test"])
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.output, "json")
        self.assertEqual(args.xss_payload, "test")

    def test_cli_parser_accepts_serve_mode(self) -> None:
        """CLI parser supports direct web-server mode."""

        args = build_arg_parser().parse_args(["--serve"])
        self.assertTrue(args.serve)

    def test_cli_parser_accepts_update_mode(self) -> None:
        """CLI parser supports update checks."""

        args = build_arg_parser().parse_args(["--update"])
        self.assertTrue(args.update)

    def test_build_update_plan_detects_changed_files(self) -> None:
        """Updater compares local and remote file contents by hash."""

        plan = build_update_plan({"app.py": "remote"}, {"app.py": "local"})
        self.assertEqual(plan[0]["path"], "app.py")
        self.assertNotEqual(plan[0]["local_sha256"], plan[0]["remote_sha256"])

    def test_filter_report_for_scan_type(self) -> None:
        """Interactive scan filters findings by selected category."""

        report = {"findings": [{"category": "xss-dom"}, {"category": "csrf"}]}
        filtered = filter_report_for_scan_type(report, "a")
        self.assertEqual(len(filtered["findings"]), 1)
        self.assertEqual(filtered["findings"][0]["category"], "xss-dom")


if __name__ == "__main__":
    unittest.main()
