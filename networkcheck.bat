@echo off
setlocal
set "SCRIPT=%~dp0..\NetworkCheck\networkcheck.ps1"
if not exist "%SCRIPT%" set "SCRIPT=%~dp0..\NetworkCheck\networkcheck.ps1"
if not exist "%SCRIPT%" (
  echo NETWORKCHECK - ERROR: networkcheck.ps1 not found. 1>&2
  exit /b 1
)
where pwsh.exe >nul 2>nul
if not errorlevel 1 (
  pwsh.exe -NoProfile -File "%SCRIPT%" %*
) else (
  powershell.exe -NoProfile -File "%SCRIPT%" %*
)
exit /b %ERRORLEVEL%
