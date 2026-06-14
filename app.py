from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import logging
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final, Iterable, Mapping, Self, TypedDict

from config import DEFAULT_CONFIG


HOST: Final[str] = DEFAULT_CONFIG.host
PORT: Final[int] = DEFAULT_CONFIG.port
MAX_BODY_BYTES: Final[int] = DEFAULT_CONFIG.max_body_bytes
MAX_PAGES_LIMIT: Final[int] = DEFAULT_CONFIG.max_pages_limit
MAX_PORT_WORKERS: Final[int] = DEFAULT_CONFIG.max_workers
BODY_PREVIEW_CHARS: Final = 4_000
USER_AGENT: Final[str] = "BGBugScout/0.2 authorized-local-scanner"

SEVERITY_ORDER: Final[dict[str, int]] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
COMMON_PORTS: Final[tuple[int, ...]] = (
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    3000,
    3306,
    3389,
    5000,
    5432,
    5601,
    5900,
    6379,
    8000,
    8080,
    8443,
    9000,
    9200,
    9300,
    11211,
    27017,
)
RISKY_FILES: Final[tuple[str, ...]] = (
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/db.sql",
    "/phpinfo.php",
    "/server-status",
    "/actuator/env",
    "/actuator/heapdump",
)
SSRF_PARAM_NAMES: Final[set[str]] = {
    "url",
    "uri",
    "path",
    "dest",
    "destination",
    "redirect",
    "next",
    "target",
    "callback",
    "webhook",
    "feed",
    "image",
    "file",
    "host",
    "domain",
    "site",
    "continue",
}
KEYWORD_PATTERNS: Final[dict[str, str]] = {
    "not-found": r"\b(404|not found|page not found|does not exist|could not be found)\b",
    "forbidden": r"\b(403|forbidden|access denied|unauthorized)\b",
    "server-error": r"\b(500|internal server error|service unavailable|bad gateway)\b",
    "debug": r"\b(debug|traceback|stack trace|exception|warning:|fatal error)\b",
    "sql-error": r"\b(sql syntax|mysql|mariadb|postgresql|sqlite|ora-\d{5}|odbc|jdbc|unclosed quotation)\b",
    "sql-dump": r"\b(create\s+table|insert\s+into|drop\s+table|alter\s+table)\b",
    "secret": r"\b(api[_-]?key|secret|private[_-]?key|access[_-]?token|client[_-]?secret)\b",
    "env-secret": r"(?im)^\s*(db_password|database_password|app_key|aws_secret|aws_secret_access_key)\s*=",
    "password": r"\b(password|passwd|pwd)\b",
    "admin": r"\b(admin|administrator|dashboard|control panel)\b",
    "login": r"\b(login|sign in|signin|log in)\b",
    "directory-listing": r"\b(index of /|parent directory|directory listing)\b",
}
DOTENV_SIGNATURE_RE: Final = re.compile(
    r"(?im)^\s*(app_key|db_password|database_url|database_password|aws_secret|aws_secret_access_key|secret_key|jwt_secret)\s*=\s*\S+"
)
SQL_DUMP_SIGNATURE_RE: Final = re.compile(
    r"(?is)\bcreate\s+table\b.+\binsert\s+into\b|\binsert\s+into\b.+\bcreate\s+table\b"
)

LOGGER = logging.getLogger("bug_finder")


class BugScoutError(Exception):
    """Base exception for scanner-specific failures."""


class TargetError(BugScoutError, ValueError):
    """Raised when a target URL or target-related scan option is invalid."""


class ScanError(BugScoutError):
    """Raised when scan execution fails after configuration has been validated."""


class ScanRequest(TypedDict):
    """JSON-compatible scan request accepted by the API layer."""

    target: str
    max_pages: int
    timeout: int
    scan_ports_enabled: bool
    custom_ports: str
    ssrf_callback: str


class ReportSummary(TypedDict):
    """Severity and artifact counts returned in a scan report."""

    pages: int
    responses: int
    findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    discovery: int


@dataclass(slots=True)
class Finding:
    """A security or quality signal found while scanning a target."""

    title: str
    severity: str
    url: str
    category: str
    detail: str
    evidence: str = ""
    remediation: str = ""


@dataclass(slots=True)
class ResponseAnalysis:
    """Normalized response metadata used for duplicate, exposure, and keyword checks."""

    url: str
    status: int | None = None
    content_type: str = ""
    normalized_content_type: str = ""
    response_body: str = ""
    response_body_truncated: bool = False
    body_size: int = 0
    content_hash: str = ""
    file_signature: str = ""
    keyword_matches: list[str] = field(default_factory=list)
    same_page_detection: str = ""
    identical_response_hash: bool = False
    identical_response_urls: list[str] = field(default_factory=list)
    content_hash_comparison: str = ""
    soft_404: bool = False
    soft_404_reason: str = ""


@dataclass(slots=True)
class PageResult:
    """A fetched page plus parsed HTML artifacts and response analysis."""

    url: str
    status: int | None = None
    content_type: str = ""
    title: str = ""
    error: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    response: ResponseAnalysis | None = None


@dataclass(slots=True)
class PortResult:
    """Result for one TCP port probe."""

    port: int
    open: bool
    banner: str = ""
    service_hint: str = ""


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Validated scan options accepted by the API and CLI entrypoints."""

    target: str
    max_pages: int
    timeout: int
    scan_ports: bool
    ports: tuple[int, ...]
    ssrf_callback: str = ""

    @classmethod
    def from_values(
        cls,
        target: str,
        max_pages: int,
        timeout: int,
        scan_ports: bool,
        ports: str,
        ssrf_callback: str,
    ) -> Self:
        """Create a bounded configuration from untrusted user-supplied values."""

        return cls(
            target=normalize_url(target),
            max_pages=max(1, min(int(max_pages), MAX_PAGES_LIMIT)),
            timeout=max(2, min(int(timeout), 20)),
            scan_ports=bool(scan_ports),
            ports=parse_ports(ports),
            ssrf_callback=ssrf_callback.strip(),
        )


class PageParser(HTMLParser):
    """Extract links, forms, scripts, and title text from a single HTML page."""

    def __init__(self, base_url: str) -> None:
        """Create a parser that resolves relative URLs against the supplied base URL."""

        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self._in_title = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect relevant attributes while the parser streams through HTML."""

        attr = {name.lower(): value or "" for name, value in attrs}
        if tag == "a" and attr.get("href"):
            self.links.append(urllib.parse.urljoin(self.base_url, attr["href"]))
        elif tag == "form":
            self.forms.append(
                {
                    "action": urllib.parse.urljoin(self.base_url, attr.get("action", self.base_url)),
                    "method": attr.get("method", "get").upper(),
                    "inputs": [],
                }
            )
        elif tag in {"input", "textarea", "select"} and self.forms:
            name = attr.get("name") or attr.get("id")
            if name:
                self.forms[-1]["inputs"].append({"name": name, "type": attr.get("type", tag)})
        elif tag == "script" and attr.get("src"):
            self.scripts.append(urllib.parse.urljoin(self.base_url, attr["src"]))
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        """Track the end of the document title."""

        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        """Append title text while inside the title element."""

        if self._in_title:
            self.title_parts.append(data.strip())

    @property
    def title(self) -> str:
        """Return the normalized page title."""

        return " ".join(part for part in self.title_parts if part).strip()


def configure_logging(level: int | str = DEFAULT_CONFIG.log_level) -> None:
    """Configure console and file logging once for local server execution."""

    if logging.getLogger().handlers:
        return
    resolved_level = logging.getLevelName(level) if isinstance(level, str) else level
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.insert(0, logging.FileHandler(DEFAULT_CONFIG.log_file, encoding="utf-8"))
    except OSError as exc:
        LOGGER.warning("File logging disabled: %s", exc)
    logging.basicConfig(
        level=resolved_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )


def normalize_url(raw_url: str) -> str:
    """Normalize and validate an HTTP or HTTPS target URL."""

    try:
        url = raw_url.strip()
        if not url:
            raise TargetError("Target URL is required.")
        if re.search(r"\s", url):
            raise TargetError(f"Invalid URL format: {raw_url}")
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = f"https://{url}"
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname or "." not in parsed.hostname:
            raise TargetError(f"Invalid URL format: {raw_url}")
        return urllib.parse.urlunparse(parsed._replace(fragment=""))
    except TargetError:
        raise
    except (TypeError, ValueError) as exc:
        raise TargetError(f"URL normalization failed: {exc}") from exc


def parse_bool(value: Any, default: bool = False) -> bool:
    """Parse common JSON/form boolean values."""

    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def parse_ports(raw_ports: str) -> tuple[int, ...]:
    """Parse comma-separated ports and ranges into a bounded sorted tuple."""

    if not raw_ports.strip() or raw_ports.strip().lower() == "common":
        return COMMON_PORTS
    ports: set[int] = set()
    try:
        for token in raw_ports.split(","):
            item = token.strip()
            if not item:
                continue
            if "-" in item:
                start_text, end_text = item.split("-", 1)
                start, end = int(start_text), int(end_text)
                if start > end:
                    raise TargetError(f"Invalid port range: {item}")
                ports.update(range(start, end + 1))
            else:
                ports.add(int(item))
    except ValueError as exc:
        raise TargetError(f"Invalid port value: {raw_ports}") from exc
    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise TargetError(f"Invalid port number: {invalid[0]}")
    if len(ports) > 100:
        raise TargetError("A scan can include at most 100 ports.")
    return tuple(sorted(ports))


def same_origin(url: str, origin: urllib.parse.ParseResult) -> bool:
    """Return True when a URL shares scheme and network location with origin."""

    parsed = urllib.parse.urlparse(url)
    return (parsed.scheme, parsed.netloc) == (origin.scheme, origin.netloc)


def is_private_host(hostname: str) -> bool:
    """Resolve a hostname and identify loopback, private, link-local, or multicast addresses."""

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        LOGGER.warning("Could not resolve hostname: %s", hostname)
        return False
    except OSError as exc:
        LOGGER.warning("Host resolution failed for %s: %s", hostname, exc)
        return False

    for info in addresses:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return True
    return False


def build_request(url: str, method: str, data: bytes | None) -> urllib.request.Request:
    """Build a scanner HTTP request with conservative default headers."""

    return urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )


def fetch_page(url: str, timeout: int, method: str = "GET", data: bytes | None = None) -> tuple[PageResult, bytes]:
    """Fetch a URL and return metadata plus a capped response body."""

    result = PageResult(url=url)
    request = build_request(url, method, data)
    try:
        context = ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            result.url = response.geturl()
            result.status = response.status
            result.headers = {key.lower(): value for key, value in response.headers.items()}
            result.content_type = result.headers.get("content-type", "")
            LOGGER.debug("Fetched %s with status %s", result.url, result.status)
            return result, response.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as exc:
        result.status = exc.code
        result.headers = {key.lower(): value for key, value in exc.headers.items()}
        result.content_type = result.headers.get("content-type", "")
        LOGGER.info("Fetched HTTP error response from %s: %s", url, exc.code)
        return result, exc.read(MAX_BODY_BYTES)
    except urllib.error.URLError as exc:
        result.error = f"URLError: {exc.reason}"
        LOGGER.warning("URL fetch failed for %s: %s", url, exc.reason)
    except TimeoutError:
        result.error = "TimeoutError: request timed out"
        LOGGER.warning("URL fetch timed out for %s", url)
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        LOGGER.warning("Network error fetching %s: %s", url, exc)
    return result, b""


def response_charset(content_type: str) -> str:
    """Extract a declared charset from a Content-Type header."""

    match = re.search(r"charset=([\w.-]+)", content_type, re.IGNORECASE)
    return match.group(1) if match else "utf-8"


def parse_html(result: PageResult, body: bytes) -> str:
    """Decode a response and parse HTML artifacts when the body looks like HTML."""

    text = body.decode(response_charset(result.content_type), errors="replace")
    if "html" in result.content_type.lower() or re.search(r"<html|<title|<form|<a\s", text, re.IGNORECASE):
        parser = PageParser(result.url)
        parser.feed(text)
        result.links = sorted(set(parser.links))
        result.forms = parser.forms
        result.scripts = sorted(set(parser.scripts))
        result.title = parser.title
    return text


def normalize_content_type(content_type: str) -> str:
    """Return a lowercase media type without parameters."""

    return content_type.split(";", 1)[0].strip().lower() or "unknown"


def is_probably_text(content_type: str, body: bytes) -> bool:
    """Detect whether a response body can safely be represented as text."""

    normalized = normalize_content_type(content_type)
    if normalized.startswith("text/"):
        return True
    if normalized in {"application/json", "application/xml", "application/javascript", "application/x-javascript", "image/svg+xml"}:
        return True
    if any(token in normalized for token in ("html", "xml", "json", "javascript")):
        return True
    return b"\x00" not in body[:512]


def detect_file_signature(body: bytes, content_type: str) -> str:
    """Classify a response body by magic bytes and high-value textual signatures."""

    if not body:
        return "empty"
    signatures: tuple[tuple[bytes, str], ...] = (
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"SQLite format 3\x00", "SQLite database"),
        (b"MZ", "Windows executable"),
        (b"\x7fELF", "ELF executable"),
    )
    for prefix, label in signatures:
        if body.startswith(prefix):
            return label

    stripped = body[:512].lstrip()
    lowered = stripped.lower()
    text_sample = body[:8192].decode("utf-8", errors="ignore")
    if lowered.startswith((b"<!doctype html", b"<html")) or b"<html" in lowered[:160]:
        return "HTML document"
    if DOTENV_SIGNATURE_RE.search(text_sample):
        return "dotenv/config file"
    if SQL_DUMP_SIGNATURE_RE.search(text_sample):
        return "SQL dump"
    if lowered.startswith(b"<?xml") or normalize_content_type(content_type).endswith("xml"):
        return "XML document"
    if lowered.startswith((b"{", b"[")) and "json" in normalize_content_type(content_type):
        return "JSON document"
    if is_probably_text(content_type, body):
        return "text response"
    return "unknown binary"


def response_body_preview(body: bytes, body_text: str, content_type: str) -> tuple[str, bool]:
    """Return a capped text or hex preview and whether the value was truncated."""

    if not body:
        return "", False
    if is_probably_text(content_type, body):
        text = body_text or body.decode("utf-8", errors="replace")
        normalized = re.sub(r"\r\n?", "\n", text)
        return normalized[:BODY_PREVIEW_CHARS], len(normalized) > BODY_PREVIEW_CHARS
    return body[:160].hex(" "), len(body) > 160


def find_keyword_matches(body_text: str) -> list[str]:
    """Return labels for security-relevant patterns found in response text."""

    return [label for label, pattern in KEYWORD_PATTERNS.items() if re.search(pattern, body_text, re.IGNORECASE)]


def analyze_response(page: PageResult, body: bytes, body_text: str) -> ResponseAnalysis:
    """Attach normalized response analysis to a page result."""

    preview, truncated = response_body_preview(body, body_text, page.content_type)
    analysis = ResponseAnalysis(
        url=page.url,
        status=page.status,
        content_type=page.content_type,
        normalized_content_type=normalize_content_type(page.content_type),
        response_body=preview,
        response_body_truncated=truncated,
        body_size=len(body),
        content_hash=hashlib.sha256(body).hexdigest() if body else "",
        file_signature=detect_file_signature(body, page.content_type),
        keyword_matches=find_keyword_matches(body_text),
    )
    page.response = analysis
    return analysis


def fetch_analyzed_page(url: str, timeout: int, method: str = "GET", data: bytes | None = None) -> tuple[PageResult, str]:
    """Fetch, parse, and analyze a URL in one call."""

    page, body = fetch_page(url, timeout, method=method, data=data)
    body_text = parse_html(page, body) if body else ""
    analyze_response(page, body, body_text)
    return page, body_text


def add_finding(findings: list[Finding], **kwargs: str) -> None:
    """Append a finding using keyword fields that match the Finding dataclass."""

    findings.append(Finding(**kwargs))


def check_headers(page: PageResult, findings: list[Finding]) -> None:
    """Report missing or risky HTTP security headers."""

    if not page.headers or page.error:
        return
    required_headers: Mapping[str, tuple[str, str]] = {
        "content-security-policy": ("Content Security Policy missing", "XSS impact can be higher without CSP."),
        "x-content-type-options": ("X-Content-Type-Options missing", "MIME sniffing protection is not advertised."),
        "referrer-policy": ("Referrer-Policy missing", "Sensitive URLs may leak through Referer headers."),
    }
    for header, (title, detail) in required_headers.items():
        if header not in page.headers:
            add_finding(
                findings,
                title=title,
                severity="low",
                url=page.url,
                category="headers",
                detail=detail,
                remediation=f"Send a suitable {header} header.",
            )
    if urllib.parse.urlparse(page.url).scheme == "https" and "strict-transport-security" not in page.headers:
        add_finding(
            findings,
            title="HSTS header missing",
            severity="medium",
            url=page.url,
            category="headers",
            detail="HTTPS responses should advertise Strict-Transport-Security.",
            remediation="Send Strict-Transport-Security after confirming HTTPS is stable across the site.",
        )


def check_response_analysis(page: PageResult, findings: list[Finding]) -> None:
    """Turn response fingerprints and keyword matches into actionable findings."""

    response = page.response
    if not response or page.status is None or page.error:
        return
    if response.normalized_content_type == "unknown":
        add_finding(
            findings,
            title="Content-Type header missing",
            severity="low",
            url=page.url,
            category="response",
            detail="The response did not include a Content-Type header.",
            remediation="Send an accurate Content-Type for every response.",
        )
    if response.file_signature == "dotenv/config file":
        add_finding(
            findings,
            title="Environment config file content exposed",
            severity="critical",
            url=page.url,
            category="secret",
            detail="The response body matches dotenv-style secret/config content.",
            evidence=", ".join(response.keyword_matches) or response.file_signature,
            remediation="Block public access immediately and rotate exposed credentials.",
        )
    if response.file_signature == "SQL dump":
        add_finding(
            findings,
            title="Database dump content exposed",
            severity="critical",
            url=page.url,
            category="exposure",
            detail="The response body looks like a SQL dump.",
            evidence=response.file_signature,
            remediation="Remove public access to database dumps and rotate affected credentials.",
        )
    risky_keywords = [
        keyword
        for keyword in response.keyword_matches
        if keyword in {"debug", "sql-error", "sql-dump", "secret", "password", "directory-listing"}
    ]
    if risky_keywords:
        severity = "critical" if {"secret", "sql-dump"} & set(risky_keywords) else "high" if "sql-error" in risky_keywords else "medium"
        add_finding(
            findings,
            title="Keyword match in response body",
            severity=severity,
            url=page.url,
            category="response",
            detail="The response body contains security-relevant keywords.",
            evidence=", ".join(risky_keywords),
            remediation="Confirm whether the matched content is intended to be public.",
        )


def response_words(text: str) -> set[str]:
    """Extract a bounded word set for soft-404 similarity checks."""

    return set(re.findall(r"[a-z0-9][a-z0-9_-]{1,}", text.lower())[:5000])


def response_similarity(left_text: str, right_text: str) -> float:
    """Return Jaccard similarity for two response texts."""

    left = response_words(left_text)
    right = response_words(right_text)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def mark_soft_404(page: PageResult, body_text: str, baseline: PageResult | None, baseline_text: str) -> bool:
    """Mark pages that look equivalent to a known missing-path baseline."""

    if not page.response or not baseline or not baseline.response:
        return False
    if page.url == baseline.url or page.status != baseline.status or not page.status or page.status >= 400:
        return False

    reasons: list[str] = []
    if page.response.content_hash and page.response.content_hash == baseline.response.content_hash:
        reasons.append("identical response hash to random missing-path baseline")
    else:
        similarity = response_similarity(body_text, baseline_text)
        size_gap = abs(page.response.body_size - baseline.response.body_size) / max(page.response.body_size, baseline.response.body_size, 1)
        if similarity >= 0.92 and size_gap <= 0.25:
            reasons.append(f"body similarity {similarity:.2f} to random missing-path baseline")
    if "not-found" in page.response.keyword_matches and page.status < 400:
        reasons.append("not-found keyword with non-error HTTP status")
    if not reasons:
        return False
    page.response.soft_404 = True
    page.response.soft_404_reason = "; ".join(reasons)
    return True


def compare_content_hashes(response_pages: Iterable[PageResult], findings: list[Finding]) -> None:
    """Annotate identical response bodies and add one informational finding per group."""

    groups: dict[str, list[PageResult]] = {}
    for page in response_pages:
        if page.response and page.response.content_hash:
            groups.setdefault(page.response.content_hash, []).append(page)

    for content_hash, pages in groups.items():
        if len(pages) < 2:
            continue
        urls = [page.response.url for page in pages if page.response]
        for page in pages:
            if not page.response:
                continue
            page.response.identical_response_hash = True
            page.response.identical_response_urls = [url for url in urls if url != page.response.url][:20]
            page.response.same_page_detection = f"Same-page candidate: identical body hash shared by {len(urls)} responses."
            page.response.content_hash_comparison = f"sha256:{content_hash[:16]}... matches {len(urls) - 1} other response(s)."
        add_finding(
            findings,
            title="Identical response body hash",
            severity="info",
            url=urls[0],
            category="response",
            detail="Multiple URLs returned the exact same response body.",
            evidence=", ".join(urls[:5]),
            remediation="Review whether these routes should return distinct content or a proper 404 status.",
        )


def check_forms(page: PageResult, findings: list[Finding], ssrf_callback: str) -> None:
    """Inspect forms for risky parameters and missing transport protections."""

    for form in page.forms:
        action = str(form.get("action", page.url))
        method = str(form.get("method", "GET")).upper()
        inputs = form.get("inputs", [])
        if urllib.parse.urlparse(action).scheme == "http":
            add_finding(
                findings,
                title="Form submits over HTTP",
                severity="medium",
                url=action,
                category="forms",
                detail="A form action uses cleartext HTTP.",
                remediation="Submit sensitive forms over HTTPS.",
            )
        risky_inputs = sorted(
            str(input_item.get("name", "")).lower()
            for input_item in inputs
            if str(input_item.get("name", "")).lower() in SSRF_PARAM_NAMES
        )
        if risky_inputs:
            evidence = ", ".join(risky_inputs)
            if ssrf_callback:
                evidence = f"{evidence}; callback configured for authorized manual validation: {ssrf_callback}"
            add_finding(
                findings,
                title="SSRF-sensitive parameter name in form",
                severity="info",
                url=action,
                category="forms",
                detail=f"A {method} form includes URL/path-like parameter names.",
                evidence=evidence,
                remediation="Validate destinations with an allowlist and block private network ranges.",
            )


class ContentAnalyzer:
    """Content fingerprinting and response similarity helpers."""

    @staticmethod
    def detect_file_type(body: bytes, content_type: str) -> str:
        """Identify the likely file type for a response body."""

        return detect_file_signature(body, content_type)

    @staticmethod
    def analyze(page: PageResult, body: bytes, body_text: str) -> ResponseAnalysis:
        """Attach response analysis to a page."""

        return analyze_response(page, body, body_text)

    @staticmethod
    def similarity(left_text: str, right_text: str) -> float:
        """Return body text similarity for duplicate and soft-404 detection."""

        return response_similarity(left_text, right_text)


class SecurityChecker:
    """Encapsulate page-level security checks and finding collection."""

    def __init__(self, ssrf_callback: str = "") -> None:
        """Create a checker with optional SSRF callback context for evidence notes."""

        self.ssrf_callback = ssrf_callback
        self.findings: list[Finding] = []

    def check_all(
        self,
        page: PageResult,
        body_text: str,
        soft_404_baseline: PageResult | None = None,
        soft_404_text: str = "",
    ) -> list[Finding]:
        """Run every page-level check and return accumulated findings."""

        self.check_headers(page)
        self.check_page_content(page, body_text)
        self.check_response_analysis(page)
        self.check_forms(page)
        if soft_404_baseline:
            mark_soft_404(page, body_text, soft_404_baseline, soft_404_text)
        return self.findings

    def check_headers(self, page: PageResult) -> None:
        """Check HTTP response headers for missing security controls."""

        check_headers(page, self.findings)

    def check_page_content(self, page: PageResult, body_text: str) -> None:
        """Reserve page-content checks that require the parsed body text."""

        if page.status and page.status >= 500 and body_text:
            LOGGER.debug("Server-error page content captured for %s", page.url)

    def check_response_analysis(self, page: PageResult) -> None:
        """Check normalized response analysis for risky content."""

        check_response_analysis(page, self.findings)

    def check_forms(self, page: PageResult) -> None:
        """Check forms for risky destinations and parameter names."""

        check_forms(page, self.findings, self.ssrf_callback)


def service_hint(port: int) -> str:
    """Return a simple service hint for common TCP ports."""

    hints = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP alternate",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }
    return hints.get(port, "unknown")


def scan_port(hostname: str, port: int, timeout: int) -> PortResult:
    """Probe one TCP port and capture a small banner when available."""

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.settimeout(1.0)
            try:
                banner = sock.recv(120).decode("utf-8", errors="replace").strip()
            except TimeoutError:
                banner = ""
            except OSError:
                banner = ""
            return PortResult(port=port, open=True, banner=banner, service_hint=service_hint(port))
    except (ConnectionRefusedError, TimeoutError, OSError):
        return PortResult(port=port, open=False, service_hint=service_hint(port))


def scan_ports(hostname: str, ports: Iterable[int], timeout: int) -> list[PortResult]:
    """Scan TCP ports with a bounded worker pool to avoid unbounded concurrency."""

    port_list = tuple(ports)
    if not port_list:
        return []
    worker_count = min(MAX_PORT_WORKERS, len(port_list))
    results: list[PortResult] = []
    LOGGER.info("Scanning %s TCP port(s) on %s with %s workers", len(port_list), hostname, worker_count)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(scan_port, hostname, port, timeout) for port in port_list]
        for future in as_completed(futures):
            result = future.result()
            if result.open:
                results.append(result)
    return sorted(results, key=lambda item: item.port)


class ConcurrentScanner:
    """Run independent page fetches with a bounded worker pool."""

    def __init__(self, max_workers: int = MAX_PORT_WORKERS) -> None:
        """Create a scanner with an explicit maximum worker count."""

        self.max_workers = max(1, min(max_workers, MAX_PORT_WORKERS))

    def scan_multiple(self, urls: list[str], timeout: int = DEFAULT_CONFIG.request_timeout) -> list[PageResult]:
        """Fetch and analyze multiple URLs concurrently."""

        if not urls:
            return []
        worker_count = min(self.max_workers, len(urls))
        results: list[PageResult] = []
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {executor.submit(fetch_analyzed_page, url, timeout): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    page, _ = future.result()
                    results.append(page)
                    LOGGER.debug("Scanned %s", url)
                except (urllib.error.URLError, TimeoutError, OSError) as exc:
                    LOGGER.error("Failed to scan %s: %s", url, exc)
        return results


def check_open_ports(ports: Iterable[PortResult], target: str, findings: list[Finding]) -> None:
    """Create findings for sensitive open services."""

    sensitive = {21, 22, 2375, 3306, 3389, 5432, 5601, 6379, 9200, 9300, 11211, 27017}
    for port in ports:
        if port.port in sensitive:
            add_finding(
                findings,
                title="Sensitive service port open",
                severity="medium",
                url=f"{target} port {port.port}",
                category="ports",
                detail=f"{port.service_hint} appears reachable.",
                evidence=port.banner,
                remediation="Restrict administrative and database services to trusted networks.",
            )


def crawl_target(config: ScanConfig) -> tuple[list[PageResult], dict[str, str]]:
    """Crawl same-origin pages breadth-first up to the configured page limit."""

    origin = urllib.parse.urlparse(config.target)
    queue: list[str] = [config.target]
    seen: set[str] = set()
    pages: list[PageResult] = []
    body_texts: dict[str, str] = {}

    while queue and len(pages) < config.max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        page, body_text = fetch_analyzed_page(url, config.timeout)
        pages.append(page)
        body_texts[page.url] = body_text
        if page.error:
            continue
        for link in page.links:
            clean_link = urllib.parse.urlunparse(urllib.parse.urlparse(link)._replace(fragment=""))
            if clean_link not in seen and same_origin(clean_link, origin) and len(seen) + len(queue) < config.max_pages * 2:
                queue.append(clean_link)
    return pages, body_texts


def check_risky_files(config: ScanConfig) -> list[PageResult]:
    """Request well-known sensitive paths without attempting exploitation."""

    base = config.target.rstrip("/")
    results: list[PageResult] = []
    for path in RISKY_FILES:
        page, _ = fetch_analyzed_page(f"{base}{path}", config.timeout)
        if page.status and page.status < 404:
            results.append(page)
    return results


def check_tls(target: str, timeout: int) -> dict[str, Any]:
    """Collect TLS certificate metadata for HTTPS targets."""

    parsed = urllib.parse.urlparse(target)
    if parsed.scheme != "https":
        return {"enabled": False, "host": parsed.hostname, "reason": "Target is not HTTPS."}
    hostname = parsed.hostname
    if not hostname:
        return {"enabled": True, "error": "Missing hostname."}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, parsed.port or 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                not_after = str(cert.get("notAfter", ""))
                return {
                    "enabled": True,
                    "host": hostname,
                    "issuer": cert.get("issuer"),
                    "subject": cert.get("subject"),
                    "not_after": not_after,
                    "protocol": tls_sock.version(),
                    "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else "",
                }
    except (ssl.SSLError, TimeoutError, OSError) as exc:
        LOGGER.warning("TLS check failed for %s: %s", hostname, exc)
        return {"enabled": True, "host": hostname, "error": f"{type(exc).__name__}: {exc}"}


def summarize(findings: Iterable[Finding], response_count: int, discovery_count: int, page_count: int = 0) -> ReportSummary:
    """Build severity and artifact counts for the report header."""

    finding_list = list(findings)
    summary: ReportSummary = {
        "pages": page_count,
        "responses": response_count,
        "findings": len(finding_list),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "discovery": discovery_count,
    }
    for finding in finding_list:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


def scan_target(
    target: str,
    max_pages: int = 8,
    timeout: int = 8,
    scan_port_flag: bool = True,
    ports: str = "",
    ssrf_callback: str = "",
) -> dict[str, Any]:
    """
    Scan an authorized web application for security issues.

    This function crawls same-origin pages, checks response headers, analyzes
    content fingerprints, probes known risky files, optionally scans TCP ports,
    and returns one JSON-serializable security report.

    Args:
        target: Target URL to scan. Missing schemes default to https://.
        max_pages: Maximum pages to crawl, clamped to 1-30.
        timeout: Request timeout in seconds, clamped to 2-20.
        scan_port_flag: Whether TCP port scanning is enabled.
        ports: Custom port list such as "80,443,8000-8010"; empty means common ports.
        ssrf_callback: Optional callback URL noted in SSRF-related evidence.

    Returns:
        A report dictionary containing target, scanned_at, duration_ms,
        findings, crawled pages, response fingerprints, open ports, TLS details,
        discovery results, and a summary count.

    Raises:
        TargetError: If the URL, host, or port configuration is invalid.
        ScanError: If an unexpected scan orchestration failure occurs.

    Example:
        >>> report = scan_target("https://example.com", 8, 8, True, "", "")
        >>> report["summary"]["critical"] >= 0
        True

    Note:
        Use only on systems you own or have explicit permission to test.
    """

    config = ScanConfig.from_values(target, max_pages, timeout, scan_port_flag, ports, ssrf_callback)
    parsed = urllib.parse.urlparse(config.target)
    if parsed.hostname and is_private_host(parsed.hostname):
        raise TargetError("Refusing to scan private, loopback, link-local, or multicast targets.")

    started = time.time()
    scanned_at = datetime.now(UTC).isoformat()
    LOGGER.info("Starting scan for %s", config.target)
    LOGGER.debug("Scan config: max_pages=%s timeout=%s scan_ports=%s ports=%s", config.max_pages, config.timeout, config.scan_ports, config.ports)

    try:
        pages, body_texts = crawl_target(config)
        risky_pages = check_risky_files(config)
        all_response_pages = pages + risky_pages
        baseline_path = f"/__bg_bug_scout_missing_{hashlib.sha1(config.target.encode()).hexdigest()[:12]}"
        baseline_page, baseline_text = fetch_analyzed_page(config.target.rstrip("/") + baseline_path, config.timeout)

        checker = SecurityChecker(config.ssrf_callback)
        for page in all_response_pages:
            body_text = body_texts.get(page.url, "")
            checker.check_all(page, body_text, baseline_page, baseline_text)
        findings = checker.findings
        compare_content_hashes(all_response_pages + [baseline_page], findings)

        port_results: list[PortResult] = []
        if config.scan_ports and parsed.hostname:
            port_results = scan_ports(parsed.hostname, config.ports, min(config.timeout, 5))
            check_open_ports(port_results, config.target, findings)

        findings.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.title, item.url))
        elapsed_ms = int((time.time() - started) * 1000)
        LOGGER.info("Found %s total findings", len(findings))
        LOGGER.info("Completed scan for %s in %sms", config.target, elapsed_ms)
        return {
            "target": config.target,
            "scanned_at": scanned_at,
            "duration_ms": elapsed_ms,
            "elapsed_ms": elapsed_ms,
            "summary": summarize(findings, len(all_response_pages), len(risky_pages), len(pages)),
            "findings": [asdict(item) for item in findings],
            "pages": [asdict(item) for item in pages],
            "responses": [asdict(item.response) for item in all_response_pages if item.response],
            "ports": [asdict(item) for item in port_results],
            "discovery": [asdict(item) for item in risky_pages],
            "tls": check_tls(config.target, config.timeout),
        }
    except BugScoutError:
        raise
    except Exception as exc:
        LOGGER.error("Scan failed for %s: %s", config.target, exc, exc_info=True)
        raise ScanError(f"Scan failed: {exc}") from exc


class ScoutHandler(BaseHTTPRequestHandler):
    """HTTP handler for the local BG Bug Scout interface and scan API."""

    server_version = "BGBugScout/0.2"

    def log_message(self, format: str, *args: object) -> None:
        """Route built-in request logs through the application logger."""

        LOGGER.info("%s - %s", self.address_string(), format % args)

    def send_json(self, status: HTTPStatus, payload: Mapping[str, Any]) -> None:
        """Serialize and send a JSON response."""

        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        """Serve the single-page local scanner UI."""

        if self.path in {"/", "/index.html"}:
            data = INDEX_HTML.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        """Handle scan requests from the browser UI."""

        if self.path != "/api/scan":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            if length > MAX_BODY_BYTES:
                self.send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Request body too large."})
                return
            payload = json.loads(self.rfile.read(length) or b"{}")
            report = scan_target(
                str(payload.get("target", "")),
                int(payload.get("max_pages", 8)),
                int(payload.get("timeout", 8)),
                parse_bool(payload.get("scan_ports"), True),
                str(payload.get("ports", "")),
                str(payload.get("ssrf_callback", "")),
            )
            self.send_json(HTTPStatus.OK, report)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except json.JSONDecodeError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON request body."})
        except BugScoutError as exc:
            LOGGER.exception("Scanner error")
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
        except OSError as exc:
            LOGGER.exception("Scan request failed")
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BG Bug Scout</title>
  <style>
    :root { color-scheme: light; --ink: #18212b; --muted: #5b6674; --line: #d6dee8; --bg: #f4f7fa; --panel: #fff; --accent: #0c7a6f; --accent-dark: #14545a; --critical: #7f1d1d; --high: #b3261e; --medium: #9a5b00; --low: #2f6b5d; --info: #435d78; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--ink); font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    header { background: #fff; border-bottom: 1px solid var(--line); }
    .wrap { width: min(1220px, calc(100% - 32px)); margin: 0 auto; }
    .topbar { min-height: 76px; display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    h1 { margin: 0; font-size: 24px; letter-spacing: 0; }
    .subtitle { margin: 4px 0 0; color: var(--muted); font-size: 14px; }
    main { display: grid; grid-template-columns: minmax(310px, 410px) 1fr; gap: 20px; padding: 24px 0 40px; align-items: start; }
    .panel, .finding, .page, .port, .response { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
    .panel { padding: 18px; }
    label { display: block; color: var(--muted); font-size: 13px; font-weight: 700; margin-bottom: 7px; }
    input { width: 100%; border: 1px solid #b8c4d0; border-radius: 6px; padding: 10px 11px; font: inherit; color: var(--ink); background: #fff; }
    input[type="checkbox"] { width: 18px; height: 18px; padding: 0; margin: 0; }
    input:focus { outline: 3px solid rgba(12, 122, 111, .2); border-color: var(--accent); }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 14px; }
    .checkrow { display: flex; align-items: center; gap: 10px; margin-top: 14px; color: var(--ink); font-weight: 650; }
    button { min-height: 42px; border: 0; border-radius: 6px; background: var(--accent); color: white; font: inherit; font-weight: 780; cursor: pointer; }
    button.primary { width: 100%; margin-top: 16px; }
    button.secondary { background: var(--accent-dark); padding: 0 15px; white-space: nowrap; }
    button:disabled { opacity: .62; cursor: wait; }
    .notice { margin: 14px 0 0; color: var(--muted); font-size: 13px; }
    .summary { display: grid; grid-template-columns: repeat(6, minmax(82px, 1fr)); gap: 10px; margin-bottom: 14px; }
    .metric { background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 12px; min-height: 74px; }
    .metric strong { display: block; font-size: 23px; line-height: 1; }
    .metric span { display: block; margin-top: 8px; color: var(--muted); font-size: 12px; }
    .tabs { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
    .tab { min-height: 36px; padding: 0 13px; background: white; color: var(--ink); border: 1px solid var(--line); }
    .tab.active { background: #18212b; color: white; border-color: #18212b; }
    .finding, .page, .port, .response { padding: 15px; margin-bottom: 10px; }
    .item-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; font-weight: 780; }
    .badge { border-radius: 999px; padding: 4px 9px; color: white; font-size: 12px; text-transform: uppercase; letter-spacing: 0; white-space: nowrap; }
    .critical { background: var(--critical); } .high { background: var(--high); } .medium { background: var(--medium); } .low { background: var(--low); } .info { background: var(--info); }
    .url { margin-top: 6px; color: var(--accent); overflow-wrap: anywhere; font-size: 13px; }
    .detail, .evidence, .remediation { margin-top: 8px; color: var(--muted); }
    .evidence { padding: 9px; background: #f1f4f7; border-radius: 6px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; overflow-wrap: anywhere; }
    .body-preview { max-height: 240px; overflow: auto; white-space: pre-wrap; }
    .pillrow { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .pill { border: 1px solid var(--line); border-radius: 999px; padding: 3px 8px; color: var(--muted); background: #f8fafc; font-size: 12px; }
    .empty { padding: 28px; text-align: center; color: var(--muted); border: 1px dashed #b8c4d0; border-radius: 8px; background: rgba(255,255,255,.66); }
    @media (max-width: 920px) { main { grid-template-columns: 1fr; } .summary { grid-template-columns: repeat(2, 1fr); } .topbar { align-items: flex-start; flex-direction: column; padding: 16px 0; } }
  </style>
</head>
<body>
  <header><div class="wrap topbar"><div><h1>BG Bug Scout</h1><p class="subtitle">Authorized scanner for web bugs, ports, exposure, and risk signals. Local only.</p></div><button class="secondary" id="downloadBtn" disabled>Download JSON</button></div></header>
  <main class="wrap">
    <section class="panel">
      <label for="target">Authorized target URL</label><input id="target" placeholder="https://example.com" autocomplete="off">
      <div class="row"><div><label for="maxPages">Max pages</label><input id="maxPages" type="number" min="1" max="30" value="8"></div><div><label for="timeout">Timeout sec</label><input id="timeout" type="number" min="2" max="20" value="8"></div></div>
      <div class="checkrow"><input id="scanPorts" type="checkbox" checked><span>Auto port scan</span></div>
      <label for="ports" style="margin-top:14px">Ports</label><input id="ports" placeholder="common, or 80,443,8000-8010">
      <label for="ssrf" style="margin-top:14px">SSRF callback URL</label><input id="ssrf" placeholder="optional https://your-callback.example/id">
      <button class="primary" id="scanBtn">Run safe scan</button>
      <p class="notice">Only scan systems you own or have permission to test. Checks are evidence-based and avoid exploitation or stress.</p>
    </section>
    <section><div class="summary" id="summary"></div><div class="tabs"><button class="tab active" data-view="findings">Findings</button><button class="tab" data-view="intel">Intel</button><button class="tab" data-view="responses">Responses</button><button class="tab" data-view="pages">Pages</button><button class="tab" data-view="ports">Ports</button></div><div id="output" class="empty">Scan results will appear here.</div></section>
  </main>
  <script>
    const scanBtn = document.querySelector("#scanBtn"), downloadBtn = document.querySelector("#downloadBtn"), output = document.querySelector("#output"), summary = document.querySelector("#summary"), tabs = document.querySelectorAll(".tab");
    let latestReport = null, activeView = "findings";
    const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
    function renderSummary(report) { if (!report) { summary.innerHTML = ""; return; } const items = [["Critical", report.summary.critical], ["High", report.summary.high], ["Medium", report.summary.medium], ["Low", report.summary.low], ["Responses", report.summary.responses || 0], ["Intel", report.summary.discovery || 0]]; summary.innerHTML = items.map(([label, value]) => `<div class="metric"><strong>${value}</strong><span>${label}</span></div>`).join(""); }
    function card(title, badge, body, klass = "response") { return `<article class="${klass}"><div class="item-title"><span>${escapeHtml(title)}</span><span class="badge ${escapeHtml(badge)}">${escapeHtml(badge)}</span></div>${body}</article>`; }
    function renderFindings(report) { if (!report.findings.length) { output.className = "empty"; output.textContent = "No findings from these checks."; return; } output.className = ""; output.innerHTML = report.findings.map((finding) => card(finding.title, finding.severity, `<div class="url">${escapeHtml(finding.url)}</div><div class="detail">${escapeHtml(finding.category)}: ${escapeHtml(finding.detail)}</div>${finding.evidence ? `<div class="evidence">${escapeHtml(finding.evidence)}</div>` : ""}${finding.remediation ? `<div class="remediation"><strong>Fix:</strong> ${escapeHtml(finding.remediation)}</div>` : ""}`, "finding")).join(""); }
    function renderPages(report) { if (!report.pages.length) { output.className = "empty"; output.textContent = "No pages crawled."; return; } output.className = ""; output.innerHTML = report.pages.map((page) => card(page.title || "Untitled page", "info", `<div class="url">${escapeHtml(page.url)}</div>${page.error ? `<div class="detail">${escapeHtml(page.error)}</div>` : ""}<div class="detail">${escapeHtml(page.status || "error")} ${escapeHtml(page.content_type || "unknown content type")}</div><div class="detail">${page.links.length} link(s), ${page.forms.length} form(s), ${page.scripts.length} script(s)</div>`, "page")).join(""); }
    function renderPorts(report) { if (!report.ports.length) { output.className = "empty"; output.textContent = "No open ports found in the selected scan set."; return; } output.className = ""; output.innerHTML = report.ports.map((port) => card(`Port ${port.port}`, "info", `<div class="detail">${escapeHtml(port.service_hint)}</div>${port.banner ? `<div class="evidence">${escapeHtml(port.banner)}</div>` : ""}`, "port")).join(""); }
    function renderIntel(report) { const tls = report.tls || {}, discoveries = report.discovery || []; output.className = ""; output.innerHTML = card("TLS Certificate", tls.error ? "medium" : "info", `<div class="detail"><strong>Host:</strong> ${escapeHtml(tls.host || report.target)}</div>${tls.reason ? `<div class="detail">${escapeHtml(tls.reason)}</div>` : ""}${tls.error ? `<div class="evidence">${escapeHtml(tls.error)}</div>` : ""}${tls.not_after ? `<div class="detail"><strong>Expires:</strong> ${escapeHtml(tls.not_after)}</div>` : ""}`) + discoveries.map((item) => card(`${item.url}`, item.status && item.status < 404 ? "info" : "low", `<div class="detail">${escapeHtml(item.status || "error")} ${escapeHtml(item.content_type || "")}</div>`)).join(""); }
    function renderResponses(report) { const responses = report.responses || []; if (!responses.length) { output.className = "empty"; output.textContent = "No response fingerprints captured."; return; } output.className = ""; output.innerHTML = responses.map((response) => { const keywords = response.keyword_matches && response.keyword_matches.length ? response.keyword_matches.map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join("") : `<span class="pill">no keyword match</span>`; return card(response.url, response.soft_404 ? "low" : "info", `<div class="detail"><strong>Content-Type:</strong> ${escapeHtml(response.content_type || "missing")}</div><div class="detail"><strong>File signature:</strong> ${escapeHtml(response.file_signature || "unknown")}</div><div class="detail"><strong>Body size:</strong> ${escapeHtml(response.body_size)} bytes</div><div class="evidence">sha256:${escapeHtml(response.content_hash || "empty")}</div><div class="pillrow">${keywords}</div>${response.soft_404 ? `<div class="detail"><strong>Soft 404:</strong> ${escapeHtml(response.soft_404_reason)}</div>` : ""}<div class="evidence body-preview">${escapeHtml(response.response_body || "")}${response.response_body_truncated ? "\n...[truncated]" : ""}</div>`); }).join(""); }
    function renderReport() { renderSummary(latestReport); if (!latestReport) return; if (activeView === "pages") renderPages(latestReport); else if (activeView === "ports") renderPorts(latestReport); else if (activeView === "responses") renderResponses(latestReport); else if (activeView === "intel") renderIntel(latestReport); else renderFindings(latestReport); }
    tabs.forEach((tab) => tab.addEventListener("click", () => { tabs.forEach((item) => item.classList.remove("active")); tab.classList.add("active"); activeView = tab.dataset.view; renderReport(); }));
    scanBtn.addEventListener("click", async () => { const body = { target: document.querySelector("#target").value.trim(), max_pages: Number(document.querySelector("#maxPages").value), timeout: Number(document.querySelector("#timeout").value), scan_ports: document.querySelector("#scanPorts").checked, ports: document.querySelector("#ports").value.trim(), ssrf_callback: document.querySelector("#ssrf").value.trim() }; scanBtn.disabled = true; downloadBtn.disabled = true; output.className = "empty"; output.textContent = "Scanning with safe probes..."; try { const response = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); const data = await response.json(); if (!response.ok) throw new Error(data.error || "Scan failed"); latestReport = data; downloadBtn.disabled = false; renderReport(); } catch (error) { latestReport = null; renderSummary(null); output.className = "empty"; output.textContent = error.message; } finally { scanBtn.disabled = false; } });
    downloadBtn.addEventListener("click", () => { if (!latestReport) return; const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = `bug-scout-${new Date().toISOString().slice(0, 10)}.json`; link.click(); URL.revokeObjectURL(url); });
  </script>
</body>
</html>
"""


def main() -> None:
    """Start the local scanner web server."""

    configure_logging()
    server = ThreadingHTTPServer((HOST, PORT), ScoutHandler)
    LOGGER.info("BG Bug Scout running at http://%s:%s", HOST, PORT)
    LOGGER.info("Use only on systems you own or have explicit permission to test.")
    server.serve_forever()


if __name__ == "__main__":
    main()
