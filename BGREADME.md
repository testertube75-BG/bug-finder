# BG Bug Scout

## Run

Double-click `start.bat`, then open:

```text
http://127.0.0.1:8765
```

Manual Windows start:

```powershell
py .\app.py
```

## What It Checks

- Response body preview
- Content-Type
- File signature
- Keyword match
- Identical response hash
- Same-page detection
- Content hash comparison
- Soft 404 detection
- Exposed `.env` patterns like `DB_PASSWORD=`, `APP_KEY=`, `AWS_SECRET=`
- Exposed `db.sql` patterns like `CREATE TABLE` and `INSERT INTO`

## Safety

Use only on websites/apps you own or have permission to test. The scanner does safe checks and does not run DoS, real RCE exploits, stealth, or bypass attacks.

## Important Files

- `app.py`: local scanner app
- `start.bat`: one-click Windows start
- `start.ps1`: PowerShell start
- `README.md`: project notes
