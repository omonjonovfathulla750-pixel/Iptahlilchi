@echo off
title CyberNet Pro — Jonli Tarmoq Serveri
cd /d "%~dp0"
echo ========================================================
echo   CYBERNET PRO — KIBERXAVFSIZLIK VA TARMOQ SERVERI
echo ========================================================
echo.
echo Server ishga tushirilmoqda: http://127.0.0.1:8000
echo.
timeout /t 2 >nul
start http://127.0.0.1:8000
python main.py
if errorlevel 1 (
    echo.
    echo Xatolik yuz berdi! Python yoki kerakli kutubxonalar mavjudligini tekshiring.
    pause
)
