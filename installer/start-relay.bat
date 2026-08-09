@echo off
REM Startet den RenkerVault Zero-Knowledge-Relay lokal.
REM Benoetigt Node.js (https://nodejs.org) auf diesem Rechner.
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo  [RenkerVault] Node.js wurde nicht gefunden.
  echo  Der Relay-Server benoetigt Node.js 18 oder neuer.
  echo  Bitte installieren: https://nodejs.org
  echo.
  pause
  exit /b 1
)
cd /d "%~dp0relay"
echo.
echo  RenkerVault Relay startet auf ws://localhost:8787 ...
echo  (Dieses Fenster offen lassen, solange der Relay laufen soll. Schliessen zum Beenden.)
echo.
node src\index.js
pause
