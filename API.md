# API Documentation

## HTTP Methods

| Method | Path | Status | Description |
| --- | --- | --- | --- |
| `GET` | `/` | `200 OK` | Serves the local scanner UI. |
| `GET` | `/index.html` | `200 OK` | Serves the local scanner UI. |
| `POST` | `/api/scan` | `200 OK` | Runs a scan and returns a JSON report. |
| `OPTIONS` | `/api/scan` | `204 No Content` | Returns allowed methods for API clients. |
| `DELETE` | Any path | `405 Method Not Allowed` | Not supported because reports are not stored server-side. |

## POST /api/scan

Scans an authorized web target and returns a JSON security report.

### Request

```json
{
  "target": "https://example.com",
  "max_pages": 8,
  "timeout": 8,
  "scan_ports": true,
  "ports": "80,443",
  "ssrf_callback": ""
}
```

### Request Fields

| Field | Type | Description |
| --- | --- | --- |
| `target` | string | Authorized target URL. Missing schemes default to `https://`. |
| `max_pages` | number | Maximum same-origin pages to crawl. Unlimited app config means the request value is not capped by a global page limit. |
| `timeout` | number | Per-request timeout in seconds. Values are clamped to 2-20. |
| `scan_ports` | boolean | Enables bounded TCP port scanning. |
| `ports` | string | `common`, empty, comma-separated ports, or ranges like `80,443,8000-8010`. Large ranges are allowed when running in unlimited mode. |
| `ssrf_callback` | string | Optional callback URL recorded in SSRF-related evidence. |

### Response

```json
{
  "target": "https://example.com",
  "scanned_at": "2026-06-14T15:30:00+00:00",
  "duration_ms": 1250,
  "findings": [],
  "pages": [],
  "responses": [],
  "ports": [],
  "discovery": [],
  "tls": {},
  "summary": {
    "pages": 1,
    "responses": 1,
    "findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "discovery": 0
  }
}
```

### Response Fields

| Field | Type | Description |
| --- | --- | --- |
| `target` | string | Normalized target URL. |
| `scanned_at` | string | ISO 8601 timestamp when the scan started. |
| `duration_ms` | number | Scan duration in milliseconds. |
| `elapsed_ms` | number | Backward-compatible alias for `duration_ms`. |
| `summary` | object | Count of pages, responses, findings, discovery items, and severity totals. |
| `findings` | array | Security findings with `title`, `severity`, `url`, `category`, `detail`, `evidence`, and `remediation`. |
| `pages` | array | Crawled page objects with URL, status, content type, title, links, forms, scripts, headers, and response analysis. |
| `responses` | array | Response fingerprints including decoded response body, hash, file signature, keyword matches, and soft-404 metadata. |
| `ports` | array | Open TCP ports with port number, service hint, and optional banner. |
| `discovery` | array | Risky-file discovery responses that were reachable. |
| `graphql` | array | Common GraphQL endpoint probes that looked reachable or GraphQL-like. |
| `tls` | object | TLS certificate metadata or TLS error details. |
| `plugins` | array | Names of loaded custom plugin modules. |
| `exports` | object | `findings_csv` and `html_report` export payloads. |

### Export Formats

The web UI can download:

| Format | Content |
| --- | --- |
| JSON | Full scan report including responses and exports |
| CSV | Findings table for spreadsheets |
| HTML | Standalone report for sharing or archiving |

Terminal mode supports the same formats:

```bash
python app.py --target https://example.com --output text
python app.py --target https://example.com --output json
python app.py --target https://example.com --output csv
python app.py --target https://example.com --output html --output-file report.html
```

### Custom Plugins

Plugin files can be placed in `plugins/*.py`. Supported hooks:

| Hook | Purpose |
| --- | --- |
| `analyze_page(page, body_text)` | Return additional Finding objects or dictionaries. |
| `finalize_report(report)` | Modify the final report dictionary after scanning. |

### Configuration Defaults

| Setting | Current Default | Limit / Options | Purpose |
| --- | --- | --- | --- |
| `host` | `127.0.0.1` | Any local bind address | Local bind address |
| `port` | `8765` | Any free local TCP port | Local app port |
| `max_body_bytes` | `unlimited` | Set an integer byte count to cap reads | Maximum response body read size |
| `max_pages_limit` | `unlimited` | Set an integer page count to cap crawls | Maximum crawl page cap |
| `max_workers` | `unlimited` | Set an integer worker count to cap concurrency | Worker count for concurrent checks |
| `request_timeout` | `8` | API clamps request values to 2-20 seconds | Default request timeout |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `LOW`, `MEDIUM`, `MIDIUM`, `HIGH`, `CRITICAL` | Logging level |
| `log_file` | `bug-scout.log` | Optional file path | Optional log file path |

### Errors

`400 Bad Request` is returned for invalid JSON, invalid URLs, private-network targets, or invalid ports.

`429 Too Many Requests` is returned when a client exceeds the local scan request rate limit.

`500 Internal Server Error` is returned for unexpected scan orchestration failures.

Only scan systems you own or have explicit permission to test.
