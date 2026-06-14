from __future__ import annotations

import unittest

import app


class UrlValidationTests(unittest.TestCase):
    """Tests for target and option normalization."""

    def test_normalize_url_adds_https_and_removes_fragment(self) -> None:
        self.assertEqual(app.normalize_url("example.com/path#section"), "https://example.com/path")

    def test_normalize_url_rejects_empty_value(self) -> None:
        with self.assertRaises(ValueError):
            app.normalize_url(" ")

    def test_parse_ports_accepts_ranges_and_sorts_unique_values(self) -> None:
        self.assertEqual(app.parse_ports("443,80,8000-8002,80"), (80, 443, 8000, 8001, 8002))

    def test_parse_ports_rejects_invalid_number(self) -> None:
        with self.assertRaises(ValueError):
            app.parse_ports("0")


class HtmlParsingTests(unittest.TestCase):
    """Tests for HTML extraction behavior."""

    def test_parse_html_extracts_title_links_forms_and_scripts(self) -> None:
        page = app.PageResult("https://example.com/root", content_type="text/html; charset=utf-8")
        body = b"""
        <html>
          <head><title>Example App</title><script src="/app.js"></script></head>
          <body>
            <a href="/next">Next</a>
            <form action="/submit" method="post">
              <input name="url">
              <textarea name="comment"></textarea>
            </form>
          </body>
        </html>
        """

        text = app.parse_html(page, body)

        self.assertIn("Example App", text)
        self.assertEqual(page.title, "Example App")
        self.assertEqual(page.links, ["https://example.com/next"])
        self.assertEqual(page.scripts, ["https://example.com/app.js"])
        self.assertEqual(page.forms[0]["action"], "https://example.com/submit")
        self.assertEqual(page.forms[0]["method"], "POST")
        self.assertEqual(page.forms[0]["inputs"][0]["name"], "url")


class ResponseAnalysisTests(unittest.TestCase):
    """Tests for body fingerprinting and finding generation."""

    def test_detect_file_signature_identifies_dotenv_content(self) -> None:
        body = b"APP_KEY=base64:abc\nDB_PASSWORD=secret\n"
        self.assertEqual(app.detect_file_signature(body, "text/plain"), "dotenv/config file")

    def test_analyze_response_records_hash_and_keywords(self) -> None:
        page = app.PageResult("https://example.com/.env", status=200, content_type="text/plain")
        analysis = app.analyze_response(page, b"DB_PASSWORD=secret", "DB_PASSWORD=secret")

        self.assertEqual(page.response, analysis)
        self.assertEqual(analysis.file_signature, "dotenv/config file")
        self.assertIn("env-secret", analysis.keyword_matches)
        self.assertTrue(analysis.content_hash)

    def test_check_response_analysis_adds_secret_finding(self) -> None:
        page = app.PageResult("https://example.com/.env", status=200, content_type="text/plain")
        app.analyze_response(page, b"DB_PASSWORD=secret", "DB_PASSWORD=secret")
        findings: list[app.Finding] = []

        app.check_response_analysis(page, findings)

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].severity, "critical")

    def test_compare_content_hashes_marks_duplicates(self) -> None:
        first = app.PageResult("https://example.com/a", status=200, content_type="text/html")
        second = app.PageResult("https://example.com/b", status=200, content_type="text/html")
        app.analyze_response(first, b"same", "same")
        app.analyze_response(second, b"same", "same")
        findings: list[app.Finding] = []

        app.compare_content_hashes([first, second], findings)

        self.assertTrue(first.response.identical_response_hash if first.response else False)
        self.assertTrue(second.response.identical_response_hash if second.response else False)
        self.assertEqual(findings[0].title, "Identical response body hash")

    def test_mark_soft_404_uses_keyword_with_success_status(self) -> None:
        baseline = app.PageResult("https://example.com/missing", status=200, content_type="text/html")
        page = app.PageResult("https://example.com/also-missing", status=200, content_type="text/html")
        app.analyze_response(baseline, b"not found", "not found")
        app.analyze_response(page, b"page not found", "page not found")

        self.assertTrue(app.mark_soft_404(page, "page not found", baseline, "not found"))
        self.assertTrue(page.response.soft_404 if page.response else False)


class FindingTests(unittest.TestCase):
    """Tests for focused finding helpers."""

    def test_check_forms_flags_ssrf_parameter_name(self) -> None:
        page = app.PageResult(
            "https://example.com",
            forms=[
                {
                    "action": "https://example.com/fetch",
                    "method": "POST",
                    "inputs": [{"name": "url", "type": "text"}],
                }
            ],
        )
        findings: list[app.Finding] = []

        app.check_forms(page, findings, "")

        self.assertEqual(findings[0].title, "SSRF-sensitive parameter name in form")
        self.assertEqual(findings[0].severity, "info")

    def test_summarize_counts_severities_and_artifacts(self) -> None:
        findings = [
            app.Finding("A", "high", "u", "c", "d"),
            app.Finding("B", "low", "u", "c", "d"),
        ]

        summary = app.summarize(findings, response_count=3, discovery_count=1)

        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["low"], 1)
        self.assertEqual(summary["responses"], 3)
        self.assertEqual(summary["discovery"], 1)


if __name__ == "__main__":
    unittest.main()
