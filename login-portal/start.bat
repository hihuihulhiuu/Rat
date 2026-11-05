@echo off
setlocal
cd /d "%~dp0"

rem Port belegt? Dann hier aendern (8080 ist oft durch andere Programme belegt).
if "%NV_PORT%"=="" set NV_PORT=8081

echo Starte Nordvale Portal auf http://127.0.0.1:%NV_PORT%/
start "" "http://127.0.0.1:%NV_PORT%/"

python server.py
if errorlevel 1 (
  echo.
  echo Server beendet mit Fehler. Port wechseln:
  echo   set NV_PORT=8082 ^&^& start.bat
  pause
)
