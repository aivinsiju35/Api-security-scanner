@echo off
echo ============================================
echo   API Security Scanner — Setup and Start
echo ============================================
echo.

echo [1/3] Installing Python dependencies...
python -m pip install fastapi "uvicorn[standard]" httpx cvss python-multipart aiofiles
if %errorlevel% neq 0 (
    echo ERROR: pip install failed. Make sure Python is installed and in PATH.
    pause
    exit /b 1
)
echo.
echo [2/3] Dependencies installed successfully!
echo.
echo [3/3] Starting API Security Scanner backend...
echo.
echo Server will start at: http://localhost:8000
echo Open frontend at:     http://localhost:8000
echo.
echo Press Ctrl+C to stop the server.
echo.

cd /d "%~dp0backend"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
