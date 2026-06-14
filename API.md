# API Documentation

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
| `max_pages` | number | Maximum same-origin pages to crawl. Values are clamped to 1-30. |
| `timeout` | number | Per-request timeout in seconds. Values are clamped to 2-20. |
| `scan_ports` | boolean | Enables bounded TCP port scanning. |
| `ports` | string | `common`, empty, comma-separated ports, or ranges like `80,443,8000-8010`. Maximum 100 ports. |
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

### Errors

`400 Bad Request` is returned for invalid JSON, invalid URLs, private-network targets, invalid ports, or more than 100 requested ports.

`500 Internal Server Error` is returned for unexpected scan orchestration failures.

Only scan systems you own or have explicit permission to test.
