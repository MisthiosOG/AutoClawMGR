@echo off
REM Restart autoclawpi service dengan binary terbaru — jalankan sebagai ADMIN
echo Stopping autoclawpi...
taskkill /F /IM autoclawpi.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo Starting service...
sc start autoclawpi >nul 2>&1
timeout /t 3 /nobreak >nul
netstat -ano | findstr ":8787.*LISTENING"
echo.
echo Selesai. PID di atas = proses service yang baru.
pause
