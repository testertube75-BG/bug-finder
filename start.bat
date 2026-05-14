@echo off
setlocal
cd /d "%~dp0"
set PYTHONDONTWRITEBYTECODE=1
where py >nul 2>nul
if %errorlevel%==0 (
  py app.py
) else (
  python app.py
)
pause
