@echo off
rem Full authorization round-trip. On a fresh machine/device, run this once
rem with a visible window so you can approve the MFA push.
setlocal
cd /d "%~dp0"
set "EXE=%~dp0.venv\Scripts\schwab-refresh.exe"
if exist "%EXE%" (
  "%EXE%" login %*
) else (
  uv run schwab-refresh login %*
)
exit /b %ERRORLEVEL%
