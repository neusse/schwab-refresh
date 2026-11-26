@echo off
rem Unattended refresh, safe for Task Scheduler.
rem Skips the network when the access token is still fresh; does a full
rem browser login only when the 7-day refresh token is almost gone.
setlocal
cd /d "%~dp0"
set "EXE=%~dp0.venv\Scripts\schwab-refresh.exe"
if exist "%EXE%" (
  "%EXE%" refresh %*
) else (
  uv run schwab-refresh refresh %*
)
exit /b %ERRORLEVEL%
