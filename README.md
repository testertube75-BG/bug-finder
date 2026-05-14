# BG Bug Scout

Local-first authorized security scanner with a simple browser UI.

## Safety Model

Use this only on assets you own or have written permission to test. The scanner is designed for non-destructive checks:

- No denial-of-service load testing.
- No real remote code execution attempts.
- No stealth, evasion, or persistence.
- No telemetry, cloud sync, hidden update channel, or backdoor.

## Checks

- Auto port scan with rate-limited TCP connect checks.
- Web crawl on the same origin.
- Security headers, cookies, CORS, CSP, HSTS, mixed content.
- Reflected XSS canary checks on query parameters and forms.
- SSRF-prone parameter detection, with optional user-provided callback URL canary.
- SQLi, LFI, path traversal, exposed file, and directory listing signals.
- DoS and RCE risk indicators from configuration/version/surface evidence only.
- Response fingerprinting: response body preview, Content-Type, file signature, keyword matches, SHA-256 content hash, identical response hash, same-page detection, content hash comparison, and soft 404 detection.
- Sensitive file signatures for exposed `.env` content such as `DB_PASSWORD=`, `APP_KEY=`, `AWS_SECRET=` and SQL dumps with `CREATE TABLE` / `INSERT INTO`.
- Critical, high, medium, low, and info severity report.

## One Click Start

Double-click:

```text
start.bat
```

Or run from PowerShell:

```powershell
.\start.ps1
```

Then open:

```text
http://127.0.0.1:8765
```

If starting manually on Windows, use:

```powershell
py .\app.py
```

## GitHub

I cannot create a GitHub account or password for you. Create/login to your own GitHub account, then I can help push this as a private repository using GitHub CLI or the GitHub website.
