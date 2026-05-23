@echo off
title SecureChat - Encrypted Chat Server
color 0B
echo.
echo  ==========================================
echo   SecureChat - Starting...
echo  ==========================================
echo.

echo  Clearing old server if running...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8765 " ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)

echo  Installing dependencies...
pip install websockets -q

echo.
echo  Launching server - browser will open automatically.
echo  Close this window to stop the server.
echo.
python server.py
echo.
echo  Server stopped.
pause
