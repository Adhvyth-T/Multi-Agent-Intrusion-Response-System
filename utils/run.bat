@echo off
REM ===================================================
REM Simple Windows Launcher - Just Double-Click This!
REM ===================================================

REM Force UTF-8 encoding (fixes Unicode errors)
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
chcp 65001 >nul 2>nul

REM Check Docker
docker ps >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker not running! Start Docker Desktop first.
    pause
    exit /b 1
)

REM Start Redis if needed
docker ps | findstr redis >nul 2>&1
if errorlevel 1 (
    echo Starting Redis...
    docker run -d -p 6379:6379 --name redis redis:alpine >nul 2>&1
    timeout /t 2 >nul
)

REM Show menu
:menu
cls
echo ===================================================
echo   Autonomous IR System - Windows Launcher
echo ===================================================
echo.
echo   1. Start IR System (main.py)
echo   2. Start Dashboard (Streamlit)
echo   3. Start Both (System + Dashboard)
echo   4. Deploy Cryptominer Attack
echo   5. Deploy All Attacks
echo   6. Stop All Attacks
echo   7. Stop Everything
echo   8. Exit
echo.
echo ===================================================
set /p choice="Enter choice (1-8): "

if "%choice%"=="1" goto start_system
if "%choice%"=="2" goto start_dashboard
if "%choice%"=="3" goto start_both
if "%choice%"=="4" goto attack_crypto
if "%choice%"=="5" goto attack_all
if "%choice%"=="6" goto stop_attacks
if "%choice%"=="7" goto stop_all
if "%choice%"=="8" goto end
goto menu

:start_system
cls
echo Starting IR System...
python main.py
pause
goto menu

:start_dashboard
cls
echo Starting Dashboard...
echo Dashboard will open at http://localhost:8501
streamlit run dashboard.py
pause
goto menu

:start_both
cls
echo Launching IR System and Dashboard in separate windows...
start "IR System" cmd /k "set PYTHONIOENCODING=utf-8 && set PYTHONUTF8=1 && chcp 65001 >nul && python main.py"
timeout /t 2 >nul
start "Dashboard" cmd /k "set PYTHONIOENCODING=utf-8 && set PYTHONUTF8=1 && chcp 65001 >nul && streamlit run dashboard.py"
echo.
echo Both services launched in new windows!
pause
goto menu

:attack_crypto
cls
echo Deploying Cryptominer Attack...
python simulate.py attack cryptominer
pause
goto menu

:attack_all
cls
echo Deploying ALL Attacks...
python simulate.py attack all
pause
goto menu

:stop_attacks
cls
echo Stopping All Attacks...
python simulate.py cleanup-all
pause
goto menu

:stop_all
cls
echo Stopping Everything...
taskkill /F /IM python.exe >nul 2>&1
python simulate.py cleanup-all >nul 2>&1
echo Done!
pause
goto menu

:end
echo.
echo Goodbye!
timeout /t 1 >nul
exit