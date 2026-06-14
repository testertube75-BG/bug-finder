# BG Bug Scout

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-unittest-2EA44F?style=for-the-badge)
![Security](https://img.shields.io/badge/Safe%20Scanning-Authorized%20Targets-0C7A6F?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

BG Bug Scout is a local web security scanner for authorized targets. It crawls pages, checks headers, fingerprints responses, detects risky exposed files, checks TLS metadata, and can run bounded TCP port scans.

> [!IMPORTANT]
> Only scan systems you own or have explicit permission to test.

## Features

| Area | Included |
| --- | --- |
| Web checks | Header checks, content fingerprints, risky file discovery, soft-404 signals |
| Response analysis | Content-Type validation, file signatures, keyword indicators, duplicate hash detection |
| Port scan | Bounded `ThreadPoolExecutor` scanning with configurable port lists |
| Safety | Private-network target blocking, body-size limits, rate limiting |
| Quality | Type hints, custom exceptions, logging, unit tests, CI workflow |

## Run Step by Step

### 1. Clone the repository

```bash
git clone https://github.com/testertube75-BG/bug-finder.git
cd bug-finder
```

### 2. Check Python version

```bash
python --version
```

Use Python 3.10 or newer.

### 3. Start the app

```bash
python app.py
```

### 4. Open the browser

Go to:

```text
http://127.0.0.1:8765/
```

### 5. Run a scan

1. Enter an authorized target URL, for example `https://example.com`.
2. Set `Max pages`, `Timeout sec`, and optional ports.
3. Click **Run safe scan**.
4. Review the **Findings**, **Intel**, **Responses**, **Pages**, and **Ports** tabs.
5. Click **Download JSON** to save the report.

## API Usage

Send a scan request to the local API:

```bash
curl -X POST http://127.0.0.1:8765/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "max_pages": 1,
    "timeout": 5,
    "scan_ports": false,
    "ports": "",
    "ssrf_callback": ""
  }'
```

More details are in [API.md](API.md).

## Run Tests

```bash
python -m unittest discover -s tests -v
```

Expected result:

```text
OK
```

## Configuration

Edit [config.py](config.py) to change runtime defaults.

| Setting | Current Default | Limit / Options | Purpose |
| --- | --- | --- | --- |
| `host` | `127.0.0.1` | Any local bind address | Local bind address |
| `port` | `8765` | Any free local TCP port | Local app port |
| `max_body_bytes` | `600000` | Bounded by default; do not set unlimited for untrusted targets | Maximum response body read size |
| `max_pages_limit` | `30` | Bounded by default; higher values increase crawl time | Maximum crawl page cap |
| `max_workers` | `5` | Bounded by default; higher values increase concurrency | Worker count for concurrent checks |
| `request_timeout` | `8` | API clamps request values to 2-20 seconds | Default request timeout |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | Logging level |
| `log_file` | `bug-scout.log` | Optional file path | Optional log file path |

> [!NOTE]
> Unlimited response size, crawl pages, or workers can make a scan slow or unstable. The app keeps bounded defaults for safety and predictable local performance.

## HTTP Methods

| Method | Path | Result |
| --- | --- | --- |
| `GET` | `/` or `/index.html` | Opens the scanner UI |
| `POST` | `/api/scan` | Runs a scan and returns JSON |
| `OPTIONS` | `/api/scan` | May be used by clients to inspect allowed API methods |
| `DELETE` | Any path | Not supported; no scan data is stored server-side |

See [API.md](API.md) for all request and response fields.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| Port already in use | Change `port` in `config.py`, then run `python app.py` again. |
| Browser cannot open app | Confirm the server is running and open `http://127.0.0.1:8765/`. |
| Scan rejected | Private, loopback, link-local, and multicast targets are blocked by design. |
| Too many requests | Wait for the rate-limit window to reset, then retry. |

## Project Files

```text
app.py                         Main local web app and scanner
config.py                      Runtime configuration
rate_limiter.py                Local request rate limiter
API.md                         API documentation
tests/                         Unit tests
.github/workflows/test.yml     CI workflow
```
