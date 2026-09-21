@echo off
REM ===========================================================================
REM  flowwatch one-click start (Windows).
REM  Double-click this file, or run:   start.cmd --port 8791 --dev WLAN
REM  It starts the interface + API on ONE port (default http://127.0.0.1:8791/).
REM  ASCII only: non-ASCII inside quoted blocks has broken this shell before.
REM ===========================================================================
setlocal
cd /d "%~dp0"

set "PY="
where python >nul 2>nul
if %ERRORLEVEL%==0 set "PY=python"

if not defined PY (
  py -3 -c "import sys" >nul 2>nul
  if not errorlevel 1 set "PY=py -3"
)

if not defined PY (
  echo.
  echo [flowwatch] Python was not found.
  echo             Install Python 3.10+ from https://www.python.org/downloads/
  echo             Important: tick "Add python.exe to PATH" during setup.
  echo.
  pause
  exit /b 1
)

%PY% run.py %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [flowwatch] run.py exited with code %RC% - see the messages above.
  pause
)
endlocal
