@echo off
setlocal enabledelayedexpansion

echo ====================================================
echo RAKSHAK-AI STARTUP
echo ====================================================

:: 1. Determine repository root
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "BACKEND=%ROOT%\backend"
set "FRONTEND=%ROOT%"

:: 3. Verify backend\app\main.py and package.json exist
if not exist "%BACKEND%\app\main.py" (
    echo [ERROR] Could not find backend\app\main.py. Are you running this from the repository root?
    pause
    exit /b 1
)
if not exist "%FRONTEND%\package.json" (
    echo [ERROR] Could not find package.json. Are you running this from the repository root?
    pause
    exit /b 1
)

:: 4 & 5. Python verification
set "PYTHON_CMD="
if exist "%BACKEND%\.venv\Scripts\python.exe" (
    set "PYTHON_CMD="%BACKEND%\.venv\Scripts\python.exe""
    echo [INFO] Found virtual environment Python at !PYTHON_CMD!
) else (
    echo [INFO] Virtual environment not found, falling back to global 'py -3.11'
    py -3.11 --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] 'py -3.11' is not available. Please install Python 3.11 or create the .venv.
        pause
        exit /b 1
    )
    py -3.11 -c "import uvicorn" >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] 'uvicorn' is not installed for the global Python 3.11. 
        echo Please create the virtual environment or run: py -3.11 -m pip install -r backend\requirements.txt
        pause
        exit /b 1
    )
    set "PYTHON_CMD=py -3.11"
)

:: 6. Verify npm
where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm is not found in PATH. Please install Node.js.
    pause
    exit /b 1
)

:: 7. Start backend
echo [INFO] Starting FastAPI Backend...
start "Rakshak Backend" /D "%BACKEND%" cmd /k "!PYTHON_CMD! -m uvicorn app.main:app --reload --port 8000"

:: 8. Start frontend
echo [INFO] Starting Next.js Frontend...
start "Rakshak Frontend" /D "%FRONTEND%" cmd /k "npm run dev"

echo [INFO] Waiting for backend (http://localhost:8000)...
set /a attempts=0
:wait_backend
curl -s -f -o nul http://localhost:8000/api/health
if errorlevel 1 (
    set /a attempts+=1
    if !attempts! geq 60 (
        echo [ERROR] Backend failed to start after 120 seconds.
        pause
        exit /b 1
    )
    ping 127.0.0.1 -n 3 >nul
    goto wait_backend
)
echo [INFO] Backend is UP.

echo [INFO] Waiting for frontend (http://localhost:3000)...
set /a attempts=0
:wait_frontend
curl -s -f -o nul http://localhost:3000
if errorlevel 1 (
    set /a attempts+=1
    if !attempts! geq 60 (
        echo [ERROR] Frontend failed to start after 120 seconds.
        pause
        exit /b 1
    )
    ping 127.0.0.1 -n 3 >nul
    goto wait_frontend
)
echo [INFO] Frontend is UP.

echo ====================================================
echo RAKSHAK-AI STARTUP COMPLETE
echo Backend: http://localhost:8000
echo Frontend: http://localhost:3000
echo ====================================================
start "" "http://localhost:3000"

ping 127.0.0.1 -n 6 >nul
exit /b 0
