@echo off
REM Windows Batch Installation Script for Network Testing Agents
REM Compatible with Windows 10 & Windows 11

echo ==========================================================
echo   Electrical Interference Investigation Agent Installer
echo   Platform: Windows 10/11
echo ==========================================================

where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python 3 was not found in PATH.
    echo Please install Python 3.9+ from python.org
    pause
    exit /b 1
)

cd /d "%~dp0"
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)

echo [*] Installing dependencies...
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo ==========================================================
echo   Installation Completed Successfully!
echo ==========================================================
echo To start Sender Agent:
echo   .venv\Scripts\python.exe sender\sender_agent.py --server http://^<FLASK_IP^>:5000
echo.
echo To start Receiver Agent:
echo   .venv\Scripts\python.exe receiver\receiver_agent.py --server http://^<FLASK_IP^>:5000
echo ==========================================================
pause
