<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&height=190&color=0:00F5FF,45:7C3AED,100:FF2BD6&text=BG%20Bug%20Scout&fontColor=FFFFFF&fontAlignY=38&desc=Digital%20Security%20Scanner%20%7C%20GraphQL%20%7C%20Plugins%20%7C%20Terminal%20Mode&descAlignY=58&animation=twinkling" alt="BG Bug Scout banner">

![Python](https://img.shields.io/badge/Python-3.10%2B-00BFFF?style=for-the-badge&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-31%20Passing-00FF88?style=for-the-badge)
![GraphQL](https://img.shields.io/badge/GraphQL-Enabled-FF2BD6?style=for-the-badge&logo=graphql&logoColor=white)
![Plugins](https://img.shields.io/badge/Plugins-Custom-7C3AED?style=for-the-badge)
![Terminal](https://img.shields.io/badge/Terminal_Mode-Ready-111827?style=for-the-badge&logo=gnubash&logoColor=00F5FF)
![License](https://img.shields.io/badge/License-MIT-2563EB?style=for-the-badge)

<h3>Authorized local scanner for web bugs, backend responses, GraphQL signals, ports, reports, and custom plugins.</h3>

<a href="API.md"><img src="https://img.shields.io/badge/API_Docs-Open-00F5FF?style=for-the-badge"></a>
<a href="#-run-step-by-step"><img src="https://img.shields.io/badge/Run_Guide-Start-00FF88?style=for-the-badge"></a>
<a href="#-terminal-only-mode"><img src="https://img.shields.io/badge/No_Browser-Terminal-FF2BD6?style=for-the-badge"></a>

</div>

> [!IMPORTANT]
> Only scan systems you own or have explicit permission to test.

## Neon Control Panel

| Signal | Status | Glow |
| --- | --- | --- |
| Web scanning | Ready | ![ready](https://img.shields.io/badge/READY-00FF88?style=flat-square) |
| Backend response viewer | Ready | ![backend](https://img.shields.io/badge/BACKEND-00F5FF?style=flat-square) |
| GraphQL probes | Ready | ![graphql](https://img.shields.io/badge/GRAPHQL-FF2BD6?style=flat-square) |
| Custom plugins | Ready | ![plugins](https://img.shields.io/badge/PLUGINS-7C3AED?style=flat-square) |
| ML-style detection | Ready | ![ml](https://img.shields.io/badge/ML_SIGNAL-FFB000?style=flat-square) |
| Terminal workflow | Ready | ![terminal](https://img.shields.io/badge/TERMINAL-111827?style=flat-square) |
| GitHub updater | Ready | ![update](https://img.shields.io/badge/UPDATE-2563EB?style=flat-square) |

## Feature Grid

| Layer | What It Does |
| --- | --- |
| **Web Checks** | Header checks, content fingerprints, risky file discovery, GraphQL probes, and soft-404 signals |
| **Response Analysis** | Decoded backend response body, Content-Type validation, file signatures, keywords, duplicate hashes |
| **Advanced Detection** | Local ML-style heuristic scoring and plugin-powered custom findings |
| **Reports** | JSON, CSV, and standalone HTML exports |
| **Port Scan** | Nmap-style TCP connect details: state, reason, service hint, banner, version guess, and latency |
| **Safety** | Private-network target blocking and local request rate limiting |
| **Quality** | Type hints, custom exceptions, logging, unit tests, and CI workflow |

## Run Step By Step

### 1. Clone

```bash
git clone https://github.com/testertube75-BG/bug-finder.git
cd bug-finder
```

### 2. Check Python

```bash
python --version
```

Use Python 3.10 or newer.

### 3. Start The App

```bash
python app.py
```

### 4. Open The UI

```text
http://127.0.0.1:8765/
```

### 5. Scan

1. Enter an authorized target URL or IP, for example `https://example.com` or `203.0.113.5`.
2. Set max pages, timeout, and optional ports or ranges.
3. Click **Run safe scan**.
4. Review **Findings**, **Intel**, **Responses**, **Pages**, and **Ports**.
5. Export as **JSON**, **CSV**, or **HTML**.

Port scan results show nmap-style details for each scanned TCP port:

```text
host:port/tcp
state: open | closed | filtered
reason: tcp-connect | connection-refused | timeout
service: HTTP, SSH, MySQL, Redis, unknown, ...
latency: milliseconds
banner/version: captured when the service exposes one
```

## API Usage

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

Full API reference: [API.md](API.md)

## Terminal-Only Mode

Run scans without opening an external browser:

```bash
python app.py --target https://example.com --max-pages 1 --output text
```

Export formats:

```bash
python app.py --target https://example.com --output json
python app.py --target https://example.com --output csv
python app.py --target https://example.com --output html --output-file report.html
```

## Update From GitHub

Use the **Update** button in the web UI to check GitHub `main` and replace changed project files locally.

```bash
python app.py --update
python app.py --apply-update
```

Restart after updating Python files:

```bash
python app.py
```

## Custom Plugins

Create Python files in a local `plugins/` folder. A plugin can expose `analyze_page(page, body_text)` and return `Finding` objects or dictionaries.

```python
def analyze_page(page, body_text):
    if "example" in body_text.lower():
        return [{
            "title": "Plugin keyword match",
            "severity": "info",
            "url": page.url,
            "category": "plugin",
            "detail": "The custom plugin matched response text.",
        }]
    return []
```

Plugins may also expose `finalize_report(report)`.

## Run Tests

```bash
python -m unittest discover -s tests -v
```

Expected:

```text
OK
```

## Configuration

Edit [config.py](config.py) to change runtime defaults.

| Setting | Current Default | Options | Purpose |
| --- | --- | --- | --- |
| `host` | `127.0.0.1` | Any local bind address | Local bind address |
| `port` | `8765` | Any free local TCP port | Local app port |
| `max_body_bytes` | `unlimited` | Integer byte cap or unlimited | Maximum response body read size |
| `max_pages_limit` | `unlimited` | Integer page cap or unlimited | Maximum crawl page cap |
| `max_workers` | `unlimited` | Integer worker cap or unlimited | Worker count for concurrent checks |
| `request_timeout` | `8` | API clamps request values to 2-20 seconds | Default request timeout |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `LOW`, `MEDIUM`, `MIDIUM`, `HIGH`, `CRITICAL` | Logging level |
| `log_file` | `bug-scout.log` | Optional file path | Optional log file path |

> [!NOTE]
> Unlimited response size, crawl pages, and workers are enabled by default for local authorized testing. Use integer caps in `config.py` for large targets.

## HTTP Methods

| Method | Path | Result |
| --- | --- | --- |
| `GET` | `/` or `/index.html` | Opens the scanner UI |
| `POST` | `/api/scan` | Runs a scan and returns JSON |
| `GET` | `/api/update` | Checks GitHub `main` for changed app files |
| `POST` | `/api/update` | Downloads changed files from GitHub `main` |
| `OPTIONS` | `/api/scan` and `/api/update` | Inspects allowed methods |
| `DELETE` | Any path | Not supported; no scan data is stored server-side |

## Troubleshooting

| Problem | Fix |
| --- | --- |
| Port already in use | Change `port` in `config.py`, then run `python app.py` again. |
| Browser cannot open app | Confirm the server is running and open `http://127.0.0.1:8765/`. |
| Scan rejected | Private, loopback, link-local, and multicast targets are blocked by design. Public IP targets and domain URLs are accepted. |
| Too many requests | Wait for the rate-limit window to reset, then retry. |
| Update applied but code looks old | Restart the app so Python reloads changed files. |

## Roadmap

- [x] GraphQL support
- [x] Custom plugins
- [x] Advanced ML detection
- [ ] Cloud deployment
- [ ] Team collaboration
- [x] Advanced reporting
- [x] Show backend server responses in scan output
- [x] Add terminal-first workflow so scans can run without opening an external browser

## Project Files

```text
app.py                         Main local web app and scanner
config.py                      Runtime configuration
rate_limiter.py                Local request rate limiter
API.md                         API documentation
tests/                         Unit tests
.github/workflows/test.yml     CI workflow
```

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&height=90&color=0:111827,50:7C3AED,100:00F5FF&text=AUTHORIZED%20SCANS%20ONLY&fontColor=FFFFFF&fontAlignY=52&animation=fadeIn" alt="Authorized scans only">

</div>
