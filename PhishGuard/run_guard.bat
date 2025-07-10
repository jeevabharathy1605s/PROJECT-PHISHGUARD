@echo off
echo Starting Chrome in debug mode...
start chrome.exe --remote-debugging-port=9222 --user-data-dir="C:\chrome-debug"

timeout /t 4 >nul
echo Running Phishing Guard...
cd /d C:\Users\HI\PhishGuard
python phishing_guard.py

pause
