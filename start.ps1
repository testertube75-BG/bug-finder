$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONDONTWRITEBYTECODE = "1"
if (Get-Command py -ErrorAction SilentlyContinue) {
    py .\app.py
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    python .\app.py
} else {
    throw "Python was not found. Install Python 3 or enable the Python launcher."
}
