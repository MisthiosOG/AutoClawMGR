@echo off
setlocal
title AutoClawPi - Server
cd /d "%~dp0"

echo ============================================
echo   AutoClawPi - OpenAI-compatible proxy
echo ============================================
echo.

REM Default password (ganti sesuai keinginan)
set PASSWORD=%WEB_PASSWORD%
set PORT=8787

echo   Menjalankan server...
echo   Panel : http://localhost:%PORT%
echo   Login : %PASSWORD%
echo   API   : /v1/chat/completions, /v1/models
echo.
echo   Tekan Ctrl+C untuk berhenti.
echo ============================================
echo.

autoclawpi.exe serve --port %PORT% --web-password %PASSWORD%

pause
