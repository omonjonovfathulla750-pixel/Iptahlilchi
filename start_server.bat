@echo off
title Tarmoq Boshqaruv Markazi (FastAPI Web Server)
cd /d "%~dp0"
echo Server ishga tushmoqda...
start http://127.0.0.1:8000
python main.py
pause
