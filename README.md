# BG Bug Scout

BG Bug Scout is a local-first security testing assistant for authorized bug bounty work, web app hardening, and defensive review. It combines safe crawling, response fingerprinting, passive intelligence, and low-impact probes in a simple browser UI.

## Important Scope Rule

Use this only on systems you own or have clear written permission to test. BG Bug Scout is designed to help find and document real security issues without destructive exploitation, denial-of-service testing, stealth, persistence, or unauthorized access.

## What It Checks

- Same-origin web crawl with off-scope redirect blocking.
- Security headers, cookies, CORS, CSP, HSTS, mixed content, and technology disclosure.
- Response fingerprinting with body preview, Content-Type, file signature, SHA-256 hash, duplicate body detection, keyword matches, and soft 404 detection.
- Low-impact reflected input probes for XSS review, SQL error signals, form reflection, SSRF-prone parameter names, and optional callback canary submission.
- Sensitive exposure checks for `.env`, `.git/config`, database dumps, backups, server status, phpinfo, and actuator endpoints.
- TLS certificate intelligence including issuer, subject, protocol, cipher, expiry date, and renewal findings.
- Passive discovery for `robots.txt`, `security.txt`, `.well-known/security.txt`, and `sitemap.xml`.
- Rate-limited TCP port checks for common services and high-risk exposure signals.
- DoS and RCE risk indicators from visible configuration, headers, banners, and surface evidence only.
- JSON report download for bug bounty notes and remediation tracking.

## What It Does Not Do

- It does not perform real exploit chains.
- It does not brute force passwords or tokens.
- It does not bypass authentication.
- It does not run destructive payloads.
- It does not perform denial-of-service or stress testing.
- It does not hide traffic or evade monitoring.

## Run

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

Manual Windows start:

```powershell
py .\app.py
```

## Telegram Session Helper

`generate_session.py` helps create a Pyrogram `STRING_SESSION` for projects that need a Telegram user session, such as voice chat music bots.

Install the helper dependencies:

```powershell
py -m pip install pyrogram tgcrypto
```

Run:

```powershell
py .\generate_session.py
```

Use only your own Telegram account. Keep the generated string secret and store it in `.env`, never in public GitHub.

## Bug Bounty Workflow

1. Confirm the target is in scope.
2. Run a safe scan with a small page limit first.
3. Review critical and high findings manually.
4. Save the JSON report.
5. Write a clear report with impact, evidence, steps to reproduce, and remediation.
6. Never include private user data unless the program rules explicitly allow it.

## Support

If this project helps you and you want to support the maintainer, use:

[GitHub Sponsors for testertube75-BG](https://github.com/sponsors/testertube75-BG)

The maintainer must enable GitHub Sponsors before payments can be received there.

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
