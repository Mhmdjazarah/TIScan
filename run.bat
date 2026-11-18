@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [!] Python 3.10+ is required: https://www.python.org/downloads/
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment...
    python -m venv .venv || goto :fail
)

echo [*] Installing / updating dependencies...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || goto :fail

if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo [*] Created .env - add your free API keys there to unlock more sources.
)

".venv\Scripts\python.exe" -m tiscan %*
exit /b %errorlevel%

:fail
echo [!] Setup failed - see the error above.
pause
exit /b 1
