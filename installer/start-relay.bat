@echo off
REM Starts the RenkerVault content-blind relay locally.
REM Requires Node.js (https://nodejs.org) on this machine.
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo  [RenkerVault] Node.js was not found.
  echo  The relay server requires Node.js 18 or newer.
  echo  Please install it: https://nodejs.org
  echo.
  pause
  exit /b 1
)
cd /d "%~dp0relay"
echo.
echo  RenkerVault relay starting on ws://localhost:8787 ...
echo  (Keep this window open while the relay should run. Close it to stop.)
echo.
node src\index.js
pause
