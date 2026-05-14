from __future__ import annotations

import html
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


HOST = "127.0.0.1"
PORT = 8765
MAX_BODY_BYTES = 600_000
MAX_PAGES_LIMIT = 30
USER_AGENT = "BGBugScout/0.1 authorized-local-scanner"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 9300, 11211, 27017]
RISKY_FILES = ["/.env", "/.git/config", "/backup.zip", "/db.sql", "/phpinfo.php", "/server-status", "/actuator/env", "/actuator/heapdump"]
XSS_CANARY = "bjxss-9f4b7"
SQLI_CANARY = "bjsqli'"
TRAVERSAL_CANARY = "../../../../etc/passwd"
SSRF_PARAM_NAMES = {"url", "uri", "path", "dest", "destination", "redirect", "next", "target", "callback", "webhook", "feed", "image", "file", "host", "domain", "site", "continue"}
BODY_PREVIEW_CHARS = 4000
KEYWORD_PATTERNS = {
    "not-found": r"\b(404|not found|page not found|does not exist|could not be found)\b",
    "forbidden": r"\b(403|forbidden|access denied|unauthorized)\b",
    "server-error": r"\b(500|internal server error|service unavailable|bad gateway)\b",
    "debug": r"\b(debug|traceback|stack trace|exception|warning:|fatal error)\b",
    "sql-error": r"\b(sql syntax|mysql|mariadb|postgresql|sqlite|ora-\d{5}|odbc|jdbc|unclosed quotation)\b",
    "sql-dump": r"\b(create\s+table|insert\s+into|drop\s+table|alter\s+table)\b",
    "secret": r"\b(api[_-]?key|secret|private[_-]?key|access[_-]?token|client[_-]?secret)\b",
    "env-secret": r"(?im)^\s*(db_password|database_password|app_key|aws_secret|aws_secret_access_key)\s*=",
    "db-password": r"(?im)^\s*db_password\s*=",
    "app-key": r"(?im)^\s*app_key\s*=",
    "aws-secret": r"(?im)^\s*(aws_secret|aws_secret_access_key)\s*=",
    "password": r"\b(password|passwd|pwd)\b",
    "admin": r"\b(admin|administrator|dashboard|control panel)\b",
    "login": r"\b(login|sign in|signin|log in)\b",
    "directory-listing": r"\b(index of /|parent directory|directory listing)\b",
}
DOTENV_SIGNATURE_RE = re.compile(
    r"(?im)^\s*(app_key|db_password|database_url|database_password|aws_secret|aws_secret_access_key|secret_key|jwt_secret)\s*=\s*\S+"
)
SQL_DUMP_SIGNATURE_RE = re.compile(r"(?is)\bcreate\s+table\b.+\binsert\s+into\b|\binsert\s+into\b.+\bcreate\s+table\b")


@dataclass
class Finding:
    title: str
    severity: str
    url: str
    category: str
    detail: str
    evidence: str = ""
    remediation: str = ""


@dataclass
class ResponseAnalysis:
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


@dataclass
class PageResult:
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


@dataclass
class PortResult:
    port: int
    open: bool
    banner: str = ""
    service_hint: str = ""


class PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self._in_title = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
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
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data.strip())

    @property
    def title(self) -> str:
        return " ".join(part for part in self.title_parts if part).strip()


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise ValueError("Target URL is required.")
    if not re.match(r"^https?://", url, re.I):
        url = f"https://{url}"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Use a valid http:// or https:// URL.")
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def same_origin(url: str, origin: urllib.parse.ParseResult) -> bool:
    parsed = urllib.parse.urlparse(url)
    return (parsed.scheme, parsed.netloc) == (origin.scheme, origin.netloc)


def is_private_host(hostname: str) -> bool:
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return True
    except Exception:
        return False
    return False


def fetch_page(url: str, timeout: int, method: str = "GET", data: bytes | None = None) -> tuple[PageResult, bytes]:
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    result = PageResult(url=url)
    try:
        context = ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            result.url = response.geturl()
            result.status = response.status
            result.headers = {key.lower(): value for key, value in response.headers.items()}
            result.content_type = result.headers.get("content-type", "")
            return result, response.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as exc:
        result.status = exc.code
        result.headers = {key.lower(): value for key, value in exc.headers.items()}
        result.content_type = result.headers.get("content-type", "")
        return result, exc.read(MAX_BODY_BYTES)
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result, b""


def parse_html(result: PageResult, body: bytes) -> str:
    charset = "utf-8"
    match = re.search(r"charset=([\w.-]+)", result.content_type, re.I)
    if match:
        charset = match.group(1)
    text = body.decode(charset, errors="replace")
    if "html" in result.content_type.lower() or re.search(r"<html|<title|<form|<a\s", text, re.I):
        parser = PageParser(result.url)
        parser.feed(text)
        result.links = sorted(set(parser.links))
        result.forms = parser.forms
        result.scripts = sorted(set(parser.scripts))
        result.title = parser.title
    return text


def normalize_content_type(content_type: str) -> str:
    return content_type.split(";", 1)[0].strip().lower() or "unknown"


def is_probably_text(content_type: str, body: bytes) -> bool:
    normalized = normalize_content_type(content_type)
    if normalized.startswith("text/"):
        return True
    if normalized in {"application/json", "application/xml", "application/javascript", "application/x-javascript", "image/svg+xml"}:
        return True
    if any(token in normalized for token in ["html", "xml", "json", "javascript"]):
        return True
    return b"\x00" not in body[:512]


def detect_file_signature(body: bytes, content_type: str) -> str:
    if not body:
        return "empty"
    signatures = [
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"PK\x05\x06", "empty ZIP archive"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"\x1f\x8b\x08", "Gzip archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"Rar!\x1a\x07\x00", "RAR archive"),
        (b"SQLite format 3\x00", "SQLite database"),
        (b"MZ", "Windows executable"),
        (b"\x7fELF", "ELF executable"),
    ]
    for prefix, label in signatures:
        if body.startswith(prefix):
            return label
    stripped = body[:512].lstrip()
    lowered = stripped.lower()
    text_sample = body[:8192].decode("utf-8", errors="ignore")
    if lowered.startswith(b"<!doctype html") or lowered.startswith(b"<html") or b"<html" in lowered[:160]:
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
    if not body:
        return "", False
    if is_probably_text(content_type, body):
        text = body_text or body.decode("utf-8", errors="replace")
        text = re.sub(r"\r\n?", "\n", text)
        return text[:BODY_PREVIEW_CHARS], len(text) > BODY_PREVIEW_CHARS
    return body[:160].hex(" "), len(body) > 160


def find_keyword_matches(body_text: str) -> list[str]:
    matches: list[str] = []
    for label, pattern in KEYWORD_PATTERNS.items():
        if re.search(pattern, body_text, re.I):
            matches.append(label)
    return matches


def analyze_response(page: PageResult, body: bytes, body_text: str) -> ResponseAnalysis:
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


def fetch_analyzed_page(url: str, timeout: int, method: str = "GET", data: bytes | None = None) -> tuple[PageResult, bytes, str]:
    page, body = fetch_page(url, timeout, method=method, data=data)
    body_text = parse_html(page, body) if body else ""
    analyze_response(page, body, body_text)
    return page, body, body_text


def response_words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9][a-z0-9_-]{1,}", text.lower())[:5000])


def response_similarity(left_text: str, right_text: str) -> float:
    left = response_words(left_text)
    right = response_words(right_text)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def mark_soft_404(
    page: PageResult,
    body_text: str,
    soft_404_page: PageResult | None,
    soft_404_text: str,
) -> bool:
    if not page.response or not soft_404_page or not soft_404_page.response:
        return False
    if page.url == soft_404_page.url:
        return False
    if page.status != soft_404_page.status or not page.status or page.status >= 400:
        return False

    reasons: list[str] = []
    if page.response.content_hash and page.response.content_hash == soft_404_page.response.content_hash:
        reasons.append("identical response hash to random missing-path baseline")
    else:
        similarity = response_similarity(body_text, soft_404_text)
        size_gap = abs(page.response.body_size - soft_404_page.response.body_size) / max(page.response.body_size, soft_404_page.response.body_size, 1)
        if similarity >= 0.92 and size_gap <= 0.25:
            reasons.append(f"body similarity {similarity:.2f} to random missing-path baseline")

    if "not-found" in page.response.keyword_matches and page.status < 400:
        reasons.append("not-found keyword with non-error HTTP status")

    if reasons:
        page.response.soft_404 = True
        page.response.soft_404_reason = "; ".join(reasons)
        return True
    return False


def check_response_analysis(page: PageResult, findings: list[Finding]) -> None:
    response = page.response
    if not response:
        return
    if page.status is None or page.error:
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
    if response.file_signature == "HTML document" and response.normalized_content_type not in {"text/html", "application/xhtml+xml", "unknown"}:
        add_finding(
            findings,
            title="Content-Type and file signature mismatch",
            severity="low",
            url=page.url,
            category="response",
            detail="The body looks like HTML, but the Content-Type says something else.",
            evidence=f"Content-Type={response.content_type}, signature={response.file_signature}",
            remediation="Make the Content-Type match the actual body.",
        )
    if response.file_signature == "dotenv/config file":
        add_finding(
            findings,
            title="Environment config file content exposed",
            severity="critical",
            url=page.url,
            category="secret",
            detail="The response body matches dotenv-style secret/config content such as DB_PASSWORD, APP_KEY, or AWS_SECRET.",
            evidence=", ".join(response.keyword_matches) or response.file_signature,
            remediation="Block public access immediately, move secrets server-side, and rotate exposed credentials.",
        )
    if response.file_signature == "SQL dump":
        add_finding(
            findings,
            title="Database dump content exposed",
            severity="critical",
            url=page.url,
            category="exposure",
            detail="The response body looks like a SQL dump with CREATE TABLE and INSERT INTO statements.",
            evidence=response.file_signature,
            remediation="Remove public access to database dumps and rotate any credentials or user data that may be exposed.",
        )
    env_keywords = {"env-secret", "db-password", "app-key", "aws-secret"}
    if env_keywords & set(response.keyword_matches):
        add_finding(
            findings,
            title="Environment secret keyword pattern",
            severity="critical",
            url=page.url,
            category="secret",
            detail="The response contains dotenv-style secret keys.",
            evidence=", ".join(keyword for keyword in response.keyword_matches if keyword in env_keywords),
            remediation="Treat as a possible secret leak, remove the file from public access, and rotate affected keys.",
        )
    risky_keywords = [
        keyword
        for keyword in response.keyword_matches
        if keyword in {"debug", "sql-error", "sql-dump", "secret", "password", "directory-listing"}
    ]
    if risky_keywords:
        severity = "critical" if ("secret" in risky_keywords or "sql-dump" in risky_keywords) else "high" if "sql-error" in risky_keywords else "medium"
        add_finding(
            findings,
            title="Keyword match in response body",
            severity=severity,
            url=page.url,
            category="response",
            detail="The response body contains security-relevant keywords.",
            evidence=", ".join(risky_keywords),
            remediation="Confirm whether the matched content is intended to be public and remove debug/secret/error output.",
        )


def compare_content_hashes(response_pages: list[PageResult], findings: list[Finding]) -> None:
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
            detail="Multiple URLs returned the exact same response body. This helps detect duplicate pages and soft 404 behavior.",
            evidence=", ".join(urls[:5]),
            remediation="Review whether these routes should return distinct content or a proper 404 status.",
        )


def add_finding(findings: list[Finding], **kwargs: str) -> None:
    findings.append(Finding(**kwargs))


def check_headers(page: PageResult, findings: list[Finding]) -> None:
    headers = page.headers
    if not headers or page.error:
        return
    required = {
        "content-security-policy": ("Content Security Policy missing", "XSS impact can be higher without CSP.", "Add a strict Content-Security-Policy."),
        "x-frame-options": ("Clickjacking protection missing", "The page may be framed by another site.", "Add X-Frame-Options or CSP frame-ancestors."),
        "x-content-type-options": ("MIME sniffing protection missing", "Browsers may guess content types.", "Add X-Content-Type-Options: nosniff."),
        "referrer-policy": ("Referrer policy missing", "URLs may leak through referrer headers.", "Add Referrer-Policy: strict-origin-when-cross-origin."),
    }
    for header, (title, detail, remediation) in required.items():
        if header not in headers:
            add_finding(findings, title=title, severity="medium", url=page.url, category="headers", detail=detail, remediation=remediation)
    if urllib.parse.urlparse(page.url).scheme == "https" and "strict-transport-security" not in headers:
        add_finding(findings, title="HSTS missing", severity="medium", url=page.url, category="headers", detail="HTTPS is used, but browsers are not instructed to enforce it on future visits.", remediation="Add Strict-Transport-Security after confirming HTTPS works everywhere.")
    csp = headers.get("content-security-policy", "")
    if "'unsafe-inline'" in csp or re.search(r"(^|[ ;])\*([ ;]|$)", csp):
        add_finding(findings, title="CSP may be too permissive", severity="low", url=page.url, category="xss", detail="CSP allows inline code or broad sources.", evidence=csp[:220], remediation="Use nonces/hashes and narrow source lists.")
    cors = headers.get("access-control-allow-origin", "")
    if cors == "*":
        add_finding(findings, title="Permissive CORS wildcard", severity="medium", url=page.url, category="cors", detail="Any origin can read responses allowed by this CORS policy.", evidence="Access-Control-Allow-Origin: *", remediation="Restrict allowed origins to trusted domains.")
    if headers.get("access-control-allow-credentials", "").lower() == "true" and cors:
        add_finding(findings, title="Credentialed CORS enabled", severity="high", url=page.url, category="cors", detail="Credentialed cross-origin reads can be dangerous if origin validation is weak.", evidence=f"ACAO={cors}", remediation="Avoid credentials in CORS or strictly validate origins.")
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if server or powered_by:
        evidence = ", ".join(value for value in [f"server={server}" if server else "", f"x-powered-by={powered_by}" if powered_by else ""] if value)
        add_finding(findings, title="Technology disclosure in headers", severity="low", url=page.url, category="info", detail="Headers reveal server or framework information.", evidence=evidence, remediation="Remove version/framework disclosure where practical.")


def check_cookies(page: PageResult, findings: list[Finding]) -> None:
    raw = [value for key, value in page.headers.items() if key == "set-cookie"]
    for cookie in raw:
        lowered = cookie.lower()
        missing: list[str] = []
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if urllib.parse.urlparse(page.url).scheme == "https" and "secure" not in lowered:
            missing.append("Secure")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            add_finding(findings, title="Cookie flags missing", severity="medium", url=page.url, category="cookies", detail=f"A Set-Cookie header is missing: {', '.join(missing)}.", evidence=cookie[:220], remediation="Set HttpOnly, Secure, and SameSite according to cookie purpose.")


def check_page_content(page: PageResult, body_text: str, findings: list[Finding]) -> None:
    parsed = urllib.parse.urlparse(page.url)
    if parsed.scheme == "http":
        add_finding(findings, title="Page served over HTTP", severity="high", url=page.url, category="transport", detail="Traffic can be observed or modified in transit.", remediation="Serve over HTTPS and redirect HTTP to HTTPS.")
    if page.forms and parsed.scheme == "http":
        add_finding(findings, title="Form submitted from insecure page", severity="high", url=page.url, category="transport", detail="Users may enter sensitive data on a page loaded without encryption.", evidence=f"{len(page.forms)} form(s) found", remediation="Move forms to HTTPS pages.")
    insecure_assets = [asset for asset in page.links + page.scripts if asset.startswith("http://")]
    if parsed.scheme == "https" and insecure_assets:
        add_finding(findings, title="Mixed content references found", severity="medium", url=page.url, category="transport", detail="HTTPS page references HTTP resources.", evidence=", ".join(insecure_assets[:3]), remediation="Load all subresources over HTTPS.")
    if re.search(r"<title>\s*index of\s*/?", body_text, re.I):
        add_finding(findings, title="Directory listing signal", severity="medium", url=page.url, category="exposure", detail="The response looks like an auto-generated directory listing.", remediation="Disable directory indexes unless intentionally public.")
    if re.search(r"(api[_-]?key|secret|access[_-]?token|private[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}", body_text, re.I):
        add_finding(findings, title="Possible secret-like value in page source", severity="critical", url=page.url, category="secret", detail="The HTML contains text resembling a credential or token.", remediation="Move secrets server-side and rotate exposed values after validation.")
    if re.search(r"(stack trace|traceback|exception|fatal error|warning: mysqli|sql syntax|ora-\d{5}|postgresql)", body_text, re.I):
        add_finding(findings, title="Error/debug information exposed", severity="medium", url=page.url, category="exposure", detail="The response contains error text that can help attackers fingerprint the app.", remediation="Disable debug output in production and return generic errors.")


def query_with_param(url: str, name: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    new_params = []
    for key, old in params:
        if key == name:
            new_params.append((key, value))
            replaced = True
        else:
            new_params.append((key, old))
    if not replaced:
        new_params.append((name, value))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_params)))


def check_query_probes(page: PageResult, timeout: int, findings: list[Finding], ssrf_callback: str) -> None:
    parsed = urllib.parse.urlparse(page.url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    probe_names = [key for key, _ in params][:8]
    if not probe_names and page.forms:
        probe_names = [field["name"] for form in page.forms for field in form.get("inputs", [])][:8]
    for name in probe_names:
        xss_url = query_with_param(page.url, name, XSS_CANARY)
        probe_page, probe_body = fetch_page(xss_url, timeout)
        text = probe_body.decode("utf-8", errors="replace")
        if XSS_CANARY in text:
            add_finding(findings, title="Reflected input canary", severity="medium", url=xss_url, category="xss", detail="A harmless canary value was reflected in the response. This is not proof of XSS, but it deserves manual review with output encoding checks.", evidence=f"parameter={name}", remediation="HTML/attribute/JS encode reflected data and add CSP.")
        sqli_url = query_with_param(page.url, name, SQLI_CANARY)
        sql_page, sql_body = fetch_page(sqli_url, timeout)
        sql_text = sql_body.decode("utf-8", errors="replace")
        if re.search(r"(sql syntax|mysql|mariadb|postgres|ora-\d{5}|sqlite|odbc|jdbc|unclosed quotation)", sql_text, re.I):
            add_finding(findings, title="SQL error signal after low-impact probe", severity="high", url=sqli_url, category="sqli", detail="A quote canary appears to trigger database-related error output.", evidence=f"parameter={name}, status={sql_page.status}", remediation="Use parameterized queries and generic error handling.")
        if name.lower() in SSRF_PARAM_NAMES:
            add_finding(findings, title="SSRF-prone parameter name", severity="medium", url=page.url, category="ssrf", detail="A parameter name suggests the server may fetch user-controlled URLs.", evidence=f"parameter={name}", remediation="Allowlist destinations, block private IP ranges, and avoid server-side fetches from untrusted input.")
            if ssrf_callback:
                ssrf_url = query_with_param(page.url, name, ssrf_callback)
                fetch_page(ssrf_url, timeout)
                add_finding(findings, title="SSRF callback canary sent", severity="info", url=ssrf_url, category="ssrf", detail="A user-provided callback URL was submitted for out-of-band verification. Check your callback server logs.", evidence=f"parameter={name}", remediation="If callback was hit by the server, restrict outbound fetch behavior.")


def check_forms(page: PageResult, timeout: int, findings: list[Finding]) -> None:
    for form in page.forms[:6]:
        inputs = form.get("inputs", [])
        if not inputs:
            continue
        data = urllib.parse.urlencode({field["name"]: XSS_CANARY for field in inputs}).encode()
        method = form.get("method", "GET").upper()
        action = form.get("action", page.url)
        if method == "GET":
            form_url = action + ("&" if "?" in action else "?") + data.decode()
            probe_page, probe_body = fetch_page(form_url, timeout)
        else:
            probe_page, probe_body = fetch_page(action, timeout, method="POST", data=data)
        text = probe_body.decode("utf-8", errors="replace")
        if XSS_CANARY in text:
            add_finding(findings, title="Form reflection canary", severity="medium", url=probe_page.url, category="xss", detail="A harmless form canary was reflected in the response.", evidence=f"method={method}, inputs={len(inputs)}", remediation="Validate input and contextually encode output.")


def check_risky_files(
    base_url: str,
    timeout: int,
    findings: list[Finding],
    soft_404_page: PageResult | None,
    soft_404_text: str,
) -> list[PageResult]:
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    probe_pages: list[PageResult] = []
    for path in RISKY_FILES:
        url = root + path
        page, _, text = fetch_analyzed_page(url, timeout)
        probe_pages.append(page)
        check_response_analysis(page, findings)
        is_soft_404 = mark_soft_404(page, text, soft_404_page, soft_404_text)
        if page.status and page.status < 400 and not is_soft_404:
            severity = "critical" if path in {"/.env", "/.git/config", "/actuator/heapdump"} else "high"
            evidence = text[:180].replace("\n", " ")
            add_finding(findings, title="Sensitive path appears exposed", severity=severity, url=url, category="exposure", detail=f"{path} returned HTTP {page.status}.", evidence=evidence, remediation="Remove public access and rotate secrets if exposure is confirmed.")
        elif is_soft_404:
            add_finding(findings, title="Risky path matched soft 404 page", severity="info", url=url, category="response", detail=f"{path} looked like the target's generic not-found response.", evidence=page.response.soft_404_reason if page.response else "", remediation="No exposure confirmed from this path; verify server returns real 404 statuses.")
    return probe_pages


def scan_ports(hostname: str, ports: list[int], timeout: float, findings: list[Finding]) -> list[PortResult]:
    results: list[PortResult] = []
    for port in ports:
        banner = ""
        is_open = False
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                is_open = True
                sock.settimeout(timeout)
                if port in {80, 8080, 8000, 5000, 9000}:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                try:
                    banner = sock.recv(160).decode("utf-8", errors="replace").strip()
                except Exception:
                    banner = ""
        except Exception:
            is_open = False
        if is_open:
            hint = service_hint(port)
            results.append(PortResult(port=port, open=True, banner=banner, service_hint=hint))
            if port in {21, 23, 445, 3389, 5900, 6379, 9200, 11211, 27017, 2375}:
                add_finding(findings, title="High-risk service exposed", severity="high", url=f"{hostname}:{port}", category="ports", detail=f"Port {port} is reachable. {hint}", evidence=banner[:180], remediation="Restrict network access, require authentication, and expose only necessary services.")
            else:
                add_finding(findings, title="Open service detected", severity="info", url=f"{hostname}:{port}", category="ports", detail=f"Port {port} is reachable. {hint}", evidence=banner[:180], remediation="Confirm the service is intended to be public.")
    return results


def service_hint(port: int) -> str:
    hints = {
        21: "FTP can expose credentials/data if misconfigured.",
        22: "SSH should be patched and key-protected.",
        23: "Telnet is insecure and should not be exposed.",
        80: "HTTP service.",
        443: "HTTPS service.",
        445: "SMB should rarely be internet-exposed.",
        2375: "Docker API without TLS is critical if unauthenticated.",
        3306: "MySQL should usually be private.",
        3389: "RDP should be protected by VPN/MFA.",
        5432: "PostgreSQL should usually be private.",
        5900: "VNC should not be public without strong controls.",
        6379: "Redis exposure is high risk.",
        9200: "Elasticsearch exposure can leak data.",
        11211: "Memcached exposure can leak data and enable abuse.",
        27017: "MongoDB should usually be private.",
    }
    return hints.get(port, "Review exposure and hardening.")


def check_dos_risk(pages: list[PageResult], findings: list[Finding]) -> None:
    for page in pages:
        if page.forms:
            headers = page.headers
            if "ratelimit-limit" not in headers and "x-ratelimit-limit" not in headers:
                add_finding(findings, title="Rate-limit signal missing on interactive page", severity="low", url=page.url, category="dos", detail="Forms/endpoints may need rate limiting. This scanner does not perform load testing.", evidence=f"{len(page.forms)} form(s)", remediation="Add server-side rate limiting, request size limits, and abuse monitoring.")


def check_rce_risk(pages: list[PageResult], ports: list[PortResult], findings: list[Finding]) -> None:
    version_patterns = [r"Apache/2\.2", r"PHP/5\.", r"OpenSSL/1\.0\.", r"nginx/1\.(0|1|2|3|4|5)\.", r"Express"]
    for page in pages:
        header_blob = " ".join(f"{k}: {v}" for k, v in page.headers.items())
        for pattern in version_patterns:
            if re.search(pattern, header_blob, re.I):
                add_finding(findings, title="Outdated technology indicator", severity="medium", url=page.url, category="rce-risk", detail="A header/banner suggests old or fingerprintable server software. This is a risk indicator, not an exploit attempt.", evidence=pattern, remediation="Verify versions and patch unsupported software.")
    for port in ports:
        if re.search(r"(debug|dev server|werkzeug|jupyter|docker)", port.banner, re.I):
            add_finding(findings, title="Remote administration/debug surface signal", severity="high", url=f"port:{port.port}", category="rce-risk", detail="A service banner suggests an administrative or debug interface.", evidence=port.banner[:180], remediation="Bind debug/admin services to localhost or VPN and enforce strong auth.")


def scan_target(raw_target: str, max_pages: int, timeout: int, scan_ports_enabled: bool, custom_ports: str, ssrf_callback: str) -> dict[str, Any]:
    target = normalize_url(raw_target)
    parsed_target = urllib.parse.urlparse(target)
    if is_private_host(parsed_target.hostname or "") and parsed_target.hostname not in {"localhost", "127.0.0.1"}:
        # This is still allowed for owned internal apps, but make it explicit in the report.
        private_notice = True
    else:
        private_notice = False
    queue = [target]
    seen: set[str] = set()
    pages: list[PageResult] = []
    findings: list[Finding] = []
    started = time.time()
    root = f"{parsed_target.scheme}://{parsed_target.netloc}"
    soft_404_url = f"{root}/__bg_missing_{int(started * 1000)}"
    soft_404_page, _, soft_404_text = fetch_analyzed_page(soft_404_url, timeout)
    if soft_404_page.response:
        soft_404_page.response.same_page_detection = "Random missing-path baseline for soft 404 comparison."
    check_response_analysis(soft_404_page, findings)
    if soft_404_page.status and soft_404_page.status < 400:
        if soft_404_page.response:
            soft_404_page.response.soft_404 = True
            soft_404_page.response.soft_404_reason = "random missing path returned non-error HTTP status"
        add_finding(
            findings,
            title="Soft 404 behavior detected",
            severity="low",
            url=soft_404_url,
            category="response",
            detail="A random missing path returned a non-error HTTP status. This can confuse scanners, users, and search engines.",
            evidence=f"status={soft_404_page.status}, content-type={soft_404_page.content_type}",
            remediation="Return a real 404/410 status for missing routes.",
        )

    while queue and len(pages) < max_pages:
        current = urllib.parse.urlunparse(urllib.parse.urlparse(queue.pop(0))._replace(fragment=""))
        if current in seen or not same_origin(current, parsed_target):
            continue
        seen.add(current)
        page, _, body_text = fetch_analyzed_page(current, timeout)
        pages.append(page)
        check_response_analysis(page, findings)
        if mark_soft_404(page, body_text, soft_404_page, soft_404_text):
            add_finding(findings, title="Soft 404 response", severity="low", url=page.url, category="response", detail="This URL resembles the target's generic missing-page response while returning a non-error status.", evidence=page.response.soft_404_reason if page.response else "", remediation="Return 404/410 for missing content and avoid routing unknown paths to a success page.")
        check_headers(page, findings)
        check_cookies(page, findings)
        check_page_content(page, body_text, findings)
        check_query_probes(page, timeout, findings, ssrf_callback.strip())
        check_forms(page, timeout, findings)
        for link in page.links:
            if same_origin(link, parsed_target) and link not in seen and len(queue) < max_pages * 2:
                queue.append(link)

    risky_probe_pages = check_risky_files(target, timeout, findings, soft_404_page, soft_404_text)
    all_response_pages = [soft_404_page] + pages + risky_probe_pages
    port_results: list[PortResult] = []
    if scan_ports_enabled and parsed_target.hostname:
        ports = parse_ports(custom_ports) if custom_ports.strip() else COMMON_PORTS
        port_results = scan_ports(parsed_target.hostname, ports, min(float(timeout), 3.0), findings)
    check_dos_risk(pages, findings)
    check_rce_risk(pages, port_results, findings)
    compare_content_hashes(all_response_pages, findings)
    if private_notice:
        add_finding(findings, title="Private/internal address target", severity="info", url=target, category="scope", detail="The target resolves to a private/internal address. Confirm you own or are authorized to test it.", remediation="Keep scans within your approved scope.")

    unique: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        unique[(finding.title, finding.url, finding.evidence)] = finding
    ordered_findings = sorted(unique.values(), key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.title, item.url))
    return {
        "target": target,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_ms": round((time.time() - started) * 1000),
        "pages": [asdict(page) for page in pages],
        "responses": [asdict(page.response) for page in all_response_pages if page.response],
        "soft_404_baseline": asdict(soft_404_page.response) if soft_404_page.response else None,
        "ports": [asdict(port) for port in port_results],
        "findings": [asdict(finding) for finding in ordered_findings],
        "summary": {
            "pages": len(pages),
            "responses": sum(1 for page in all_response_pages if page.response),
            "soft_404": sum(1 for page in all_response_pages if page.response and page.response.soft_404),
            "identical_hashes": sum(1 for page in all_response_pages if page.response and page.response.identical_response_hash),
            "keyword_matches": sum(1 for page in all_response_pages if page.response and page.response.keyword_matches),
            "ports_open": len(port_results),
            "findings": len(ordered_findings),
            "critical": sum(1 for item in ordered_findings if item.severity == "critical"),
            "high": sum(1 for item in ordered_findings if item.severity == "high"),
            "medium": sum(1 for item in ordered_findings if item.severity == "medium"),
            "low": sum(1 for item in ordered_findings if item.severity == "low"),
            "info": sum(1 for item in ordered_findings if item.severity == "info"),
        },
    }


def parse_ports(raw: str) -> list[int]:
    ports: set[int] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = [int(value.strip()) for value in chunk.split("-", 1)]
            for port in range(max(1, start), min(65535, end) + 1):
                ports.add(port)
        else:
            port = int(chunk)
            if 1 <= port <= 65535:
                ports.add(port)
    if len(ports) > 200:
        raise ValueError("Port list too large. Keep it under 200 ports for safe rate-limited scans.")
    return sorted(ports)


class ScoutHandler(BaseHTTPRequestHandler):
    server_version = "BGBugScout/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
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
        if self.path != "/api/scan":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            max_pages = max(1, min(int(payload.get("max_pages", 8)), MAX_PAGES_LIMIT))
            timeout = max(2, min(int(payload.get("timeout", 8)), 20))
            report = scan_target(
                str(payload.get("target", "")),
                max_pages,
                timeout,
                bool(payload.get("scan_ports", True)),
                str(payload.get("ports", "")),
                str(payload.get("ssrf_callback", "")),
            )
            self.send_json(HTTPStatus.OK, report)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BG Bug Scout</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #18212b;
      --muted: #5b6674;
      --line: #d6dee8;
      --bg: #f4f7fa;
      --panel: #fff;
      --accent: #0c7a6f;
      --accent-dark: #14545a;
      --critical: #7f1d1d;
      --high: #b3261e;
      --medium: #9a5b00;
      --low: #2f6b5d;
      --info: #435d78;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      background: #fff;
      border-bottom: 1px solid var(--line);
    }
    .wrap {
      width: min(1220px, calc(100% - 32px));
      margin: 0 auto;
    }
    .topbar {
      min-height: 76px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
    }
    h1 {
      margin: 0;
      font-size: 24px;
      letter-spacing: 0;
    }
    .subtitle {
      margin: 4px 0 0;
      color: var(--muted);
      font-size: 14px;
    }
    main {
      display: grid;
      grid-template-columns: minmax(310px, 410px) 1fr;
      gap: 20px;
      padding: 24px 0 40px;
      align-items: start;
    }
    .panel, .finding, .page, .port, .response {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .panel {
      padding: 18px;
    }
    label {
      display: block;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      margin-bottom: 7px;
    }
    input {
      width: 100%;
      border: 1px solid #b8c4d0;
      border-radius: 6px;
      padding: 10px 11px;
      font: inherit;
      color: var(--ink);
      background: #fff;
    }
    input[type="checkbox"] {
      width: 18px;
      height: 18px;
      padding: 0;
      margin: 0;
    }
    input:focus {
      outline: 3px solid rgba(12, 122, 111, .2);
      border-color: var(--accent);
    }
    .row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-top: 14px;
    }
    .checkrow {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-top: 14px;
      color: var(--ink);
      font-weight: 650;
    }
    button {
      min-height: 42px;
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: white;
      font: inherit;
      font-weight: 780;
      cursor: pointer;
    }
    button.primary {
      width: 100%;
      margin-top: 16px;
    }
    button.secondary {
      background: var(--accent-dark);
      padding: 0 15px;
      white-space: nowrap;
    }
    button:disabled {
      opacity: .62;
      cursor: wait;
    }
    .notice {
      margin: 14px 0 0;
      color: var(--muted);
      font-size: 13px;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(6, minmax(82px, 1fr));
      gap: 10px;
      margin-bottom: 14px;
    }
    .metric {
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      min-height: 74px;
    }
    .metric strong {
      display: block;
      font-size: 23px;
      line-height: 1;
    }
    .metric span {
      display: block;
      margin-top: 8px;
      color: var(--muted);
      font-size: 12px;
    }
    .tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    .tab {
      min-height: 36px;
      padding: 0 13px;
      background: white;
      color: var(--ink);
      border: 1px solid var(--line);
    }
    .tab.active {
      background: #18212b;
      color: white;
      border-color: #18212b;
    }
    .finding, .page, .port, .response {
      padding: 15px;
      margin-bottom: 10px;
    }
    .item-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      font-weight: 780;
    }
    .badge {
      border-radius: 999px;
      padding: 4px 9px;
      color: white;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
      white-space: nowrap;
    }
    .critical { background: var(--critical); }
    .high { background: var(--high); }
    .medium { background: var(--medium); }
    .low { background: var(--low); }
    .info { background: var(--info); }
    .url {
      margin-top: 6px;
      color: var(--accent);
      overflow-wrap: anywhere;
      font-size: 13px;
    }
    .detail, .evidence, .remediation {
      margin-top: 8px;
      color: var(--muted);
    }
    .evidence {
      padding: 9px;
      background: #f1f4f7;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      overflow-wrap: anywhere;
    }
    .body-preview {
      max-height: 240px;
      overflow: auto;
      white-space: pre-wrap;
    }
    .pillrow {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }
    .pill {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px 8px;
      color: var(--muted);
      background: #f8fafc;
      font-size: 12px;
    }
    .empty {
      padding: 28px;
      text-align: center;
      color: var(--muted);
      border: 1px dashed #b8c4d0;
      border-radius: 8px;
      background: rgba(255,255,255,.66);
    }
    @media (max-width: 920px) {
      main { grid-template-columns: 1fr; }
      .summary { grid-template-columns: repeat(2, 1fr); }
      .topbar { align-items: flex-start; flex-direction: column; padding: 16px 0; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <div>
        <h1>BG Bug Scout</h1>
        <p class="subtitle">Authorized scanner for web bugs, ports, exposure, and risk signals. Local only.</p>
      </div>
      <button class="secondary" id="downloadBtn" disabled>Download JSON</button>
    </div>
  </header>
  <main class="wrap">
    <section class="panel">
      <label for="target">Authorized target URL</label>
      <input id="target" placeholder="https://example.com" autocomplete="off">
      <div class="row">
        <div>
          <label for="maxPages">Max pages</label>
          <input id="maxPages" type="number" min="1" max="30" value="8">
        </div>
        <div>
          <label for="timeout">Timeout sec</label>
          <input id="timeout" type="number" min="2" max="20" value="8">
        </div>
      </div>
      <div class="checkrow">
        <input id="scanPorts" type="checkbox" checked>
        <span>Auto port scan</span>
      </div>
      <label for="ports" style="margin-top:14px">Ports</label>
      <input id="ports" placeholder="common, or 80,443,8000-8010">
      <label for="ssrf" style="margin-top:14px">SSRF callback URL</label>
      <input id="ssrf" placeholder="optional https://your-callback.example/id">
      <button class="primary" id="scanBtn">Run safe scan</button>
      <p class="notice">Only scan systems you own or have permission to test. DoS and RCE checks are evidence-based and do not exploit or stress the target.</p>
    </section>
    <section>
      <div class="summary" id="summary"></div>
      <div class="tabs">
        <button class="tab active" data-view="findings">Findings</button>
        <button class="tab" data-view="responses">Responses</button>
        <button class="tab" data-view="pages">Pages</button>
        <button class="tab" data-view="ports">Ports</button>
      </div>
      <div id="output" class="empty">Scan results will appear here.</div>
    </section>
  </main>
  <script>
    const scanBtn = document.querySelector("#scanBtn");
    const downloadBtn = document.querySelector("#downloadBtn");
    const output = document.querySelector("#output");
    const summary = document.querySelector("#summary");
    const tabs = document.querySelectorAll(".tab");
    let latestReport = null;
    let activeView = "findings";

    const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[char]));

    function renderSummary(report) {
      if (!report) {
        summary.innerHTML = "";
        return;
      }
      const items = [
        ["Critical", report.summary.critical],
        ["High", report.summary.high],
        ["Medium", report.summary.medium],
        ["Low", report.summary.low],
        ["Responses", report.summary.responses || 0],
        ["Soft 404", report.summary.soft_404 || 0],
      ];
      summary.innerHTML = items.map(([label, value]) => `<div class="metric"><strong>${value}</strong><span>${label}</span></div>`).join("");
    }

    function renderFindings(report) {
      if (!report.findings.length) {
        output.className = "empty";
        output.textContent = "No findings from these checks.";
        return;
      }
      output.className = "";
      output.innerHTML = report.findings.map((finding) => `
        <article class="finding">
          <div class="item-title">
            <span>${escapeHtml(finding.title)}</span>
            <span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
          </div>
          <div class="url">${escapeHtml(finding.url)}</div>
          <div class="detail">${escapeHtml(finding.category)}: ${escapeHtml(finding.detail)}</div>
          ${finding.evidence ? `<div class="evidence">${escapeHtml(finding.evidence)}</div>` : ""}
          ${finding.remediation ? `<div class="remediation"><strong>Fix:</strong> ${escapeHtml(finding.remediation)}</div>` : ""}
        </article>
      `).join("");
    }

    function renderPages(report) {
      if (!report.pages.length) {
        output.className = "empty";
        output.textContent = "No pages crawled.";
        return;
      }
      output.className = "";
      output.innerHTML = report.pages.map((page) => `
        <article class="page">
          <div class="item-title">
            <span>${escapeHtml(page.title || "Untitled page")}</span>
            <span class="badge info">${escapeHtml(page.status || "error")}</span>
          </div>
          <div class="url">${escapeHtml(page.url)}</div>
          ${page.error ? `<div class="detail">${escapeHtml(page.error)}</div>` : ""}
          <div class="detail">${escapeHtml(page.content_type || "unknown content type")}</div>
          <div class="detail">${page.links.length} link(s), ${page.forms.length} form(s), ${page.scripts.length} script(s)</div>
        </article>
      `).join("");
    }

    function renderPorts(report) {
      if (!report.ports.length) {
        output.className = "empty";
        output.textContent = "No open ports found in the selected scan set.";
        return;
      }
      output.className = "";
      output.innerHTML = report.ports.map((port) => `
        <article class="port">
          <div class="item-title">
            <span>Port ${escapeHtml(port.port)}</span>
            <span class="badge info">open</span>
          </div>
          <div class="detail">${escapeHtml(port.service_hint)}</div>
          ${port.banner ? `<div class="evidence">${escapeHtml(port.banner)}</div>` : ""}
        </article>
      `).join("");
    }

    function renderResponses(report) {
      const responses = report.responses || [];
      if (!responses.length) {
        output.className = "empty";
        output.textContent = "No response fingerprints captured.";
        return;
      }
      output.className = "";
      output.innerHTML = responses.map((response) => {
        const keywords = response.keyword_matches && response.keyword_matches.length
          ? response.keyword_matches.map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join("")
          : `<span class="pill">no keyword match</span>`;
        const matches = response.identical_response_urls && response.identical_response_urls.length
          ? `<div class="detail">Identical URLs: ${escapeHtml(response.identical_response_urls.join(", "))}</div>`
          : "";
        return `
          <article class="response">
            <div class="item-title">
              <span>${escapeHtml(response.url)}</span>
              <span class="badge ${response.soft_404 ? "low" : "info"}">${escapeHtml(response.status || "error")}</span>
            </div>
            <div class="detail"><strong>Content-Type:</strong> ${escapeHtml(response.content_type || "missing")}</div>
            <div class="detail"><strong>File signature:</strong> ${escapeHtml(response.file_signature || "unknown")}</div>
            <div class="detail"><strong>Body size:</strong> ${escapeHtml(response.body_size)} bytes</div>
            <div class="evidence">sha256:${escapeHtml(response.content_hash || "empty")}</div>
            <div class="pillrow">${keywords}</div>
            ${response.same_page_detection ? `<div class="detail"><strong>Same-page detection:</strong> ${escapeHtml(response.same_page_detection)}</div>` : ""}
            ${response.content_hash_comparison ? `<div class="detail"><strong>Content hash comparison:</strong> ${escapeHtml(response.content_hash_comparison)}</div>` : ""}
            ${matches}
            ${response.soft_404 ? `<div class="detail"><strong>Soft 404:</strong> ${escapeHtml(response.soft_404_reason)}</div>` : ""}
            <div class="evidence body-preview">${escapeHtml(response.response_body || "")}${response.response_body_truncated ? "\n...[truncated]" : ""}</div>
          </article>
        `;
      }).join("");
    }

    function renderReport() {
      renderSummary(latestReport);
      if (!latestReport) return;
      if (activeView === "pages") renderPages(latestReport);
      else if (activeView === "ports") renderPorts(latestReport);
      else if (activeView === "responses") renderResponses(latestReport);
      else renderFindings(latestReport);
    }

    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.forEach((item) => item.classList.remove("active"));
        tab.classList.add("active");
        activeView = tab.dataset.view;
        renderReport();
      });
    });

    scanBtn.addEventListener("click", async () => {
      const body = {
        target: document.querySelector("#target").value.trim(),
        max_pages: Number(document.querySelector("#maxPages").value),
        timeout: Number(document.querySelector("#timeout").value),
        scan_ports: document.querySelector("#scanPorts").checked,
        ports: document.querySelector("#ports").value.trim(),
        ssrf_callback: document.querySelector("#ssrf").value.trim()
      };
      scanBtn.disabled = true;
      downloadBtn.disabled = true;
      output.className = "empty";
      output.textContent = "Scanning with safe probes...";
      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Scan failed");
        latestReport = data;
        downloadBtn.disabled = false;
        renderReport();
      } catch (error) {
        latestReport = null;
        renderSummary(null);
        output.className = "empty";
        output.textContent = error.message;
      } finally {
        scanBtn.disabled = false;
      }
    });

    downloadBtn.addEventListener("click", () => {
      if (!latestReport) return;
      const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `bug-scout-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      URL.revokeObjectURL(url);
    });
  </script>
</body>
</html>
"""


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), ScoutHandler)
    print(f"BG Bug Scout running at http://{HOST}:{PORT}")
    print("Use only on systems you own or have explicit permission to test.")
    server.serve_forever()


if __name__ == "__main__":
    main()
