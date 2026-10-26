@echo off
setlocal EnableExtensions EnableDelayedExpansion
title AndroShield
cd /d "%~dp0"

set "PROJECT_ROOT=%CD%"
set "BACKEND=%PROJECT_ROOT%\backend"
set "PYTHON=%BACKEND%\.venv\Scripts\python.exe"
set "DASHBOARD=http://127.0.0.1:8000"
set "ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"
set "EMULATOR=%LOCALAPPDATA%\Android\Sdk\emulator\emulator.exe"

echo.
echo ============================================================
echo   AndroShield
echo ============================================================
echo.

rem Create the Python environment on the first run.
if not exist "%PYTHON%" (
    echo [SETUP] Creating backend Python environment...
    where python >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python was not found. Install Python 3.11 or newer.
        pause
        exit /b 1
    )
    python -m venv "%BACKEND%\.venv"
    if errorlevel 1 goto :setup_failed
    "%PYTHON%" -m pip install --upgrade pip
    if errorlevel 1 goto :setup_failed
    "%PYTHON%" -m pip install -r "%BACKEND%\requirements.txt"
    if errorlevel 1 goto :setup_failed
)

if not exist "%BACKEND%\.env" (
    echo [SETUP] Creating backend\.env from .env.example...
    copy /y "%BACKEND%\.env.example" "%BACKEND%\.env" >nul
)

rem Start Ollama when installed. Static analysis remains available without it.
where ollama >nul 2>&1
if errorlevel 1 (
    echo [WARN] Ollama is not installed. Local AI features will be unavailable.
) else (
    curl.exe -fsS http://127.0.0.1:11434/api/tags >nul 2>&1
    if errorlevel 1 (
        for /f "delims=" %%I in ('where ollama') do if not defined OLLAMA_EXE set "OLLAMA_EXE=%%I"
        for %%I in ("!OLLAMA_EXE!") do set "OLLAMA_APP=%%~dpIollama app.exe"
        echo [START] Starting the Ollama application...
        if exist "!OLLAMA_APP!" (
            start "Ollama" /min "!OLLAMA_APP!"
        ) else (
            start "Ollama" /min "!OLLAMA_EXE!" serve
        )
        ping 127.0.0.1 -n 4 >nul
    ) else (
        echo [OK] Ollama is running.
    )
    curl.exe -fsS http://127.0.0.1:11434/api/tags >nul 2>&1
    if errorlevel 1 (
        echo [WARN] Ollama did not become ready. Static analysis will still work.
    ) else (
        ollama list 2>nul | findstr /b /c:"qwen3-vl:2b-instruct" >nul
        if errorlevel 1 echo [WARN] Vision model missing: ollama pull qwen3-vl:2b-instruct
        ollama list 2>nul | findstr /b /c:"qwen3:8b" >nul
        if errorlevel 1 echo [WARN] Investigation model missing: ollama pull qwen3:8b
    )
)

rem Boot only the dedicated malware-analysis AVD. Never auto-select another device.
if exist "%ADB%" if exist "%EMULATOR%" (
    powershell.exe -NoProfile -Command "$adb=$env:LOCALAPPDATA+'\Android\Sdk\platform-tools\adb.exe'; $found=$false; foreach($line in & $adb devices) { if($line -match '^(emulator-\d+)\s+') { $serial=$Matches[1]; $name=& $adb -s $serial emu avd name 2>$null; if($name -contains 'FraudSandbox'){$found=$true} } }; if($found){exit 0}else{exit 1}" >nul 2>&1
    if errorlevel 1 (
        "%EMULATOR%" -list-avds | findstr /x /i "FraudSandbox" >nul
        if errorlevel 1 (
            echo [WARN] FraudSandbox AVD was not found. Static analysis will still work.
            echo        Create it with scripts\setup_sandbox.ps1 when dynamic analysis is needed.
        ) else (
            echo [START] Booting the dedicated FraudSandbox emulator...
            start "FraudSandbox" "%EMULATOR%" -avd FraudSandbox -gpu swiftshader_indirect
        )
    ) else (
        echo [OK] FraudSandbox emulator is running.
    )
) else (
    echo [WARN] Android SDK emulator was not found. Static analysis will still work.
)

if /i "%~1"=="--check" (
    echo.
    echo [OK] Prerequisite check completed.
    exit /b 0
)

rem Open the browser only after the health endpoint starts responding.
start "Dashboard launcher" /min powershell.exe -NoProfile -WindowStyle Hidden -Command "$url='%DASHBOARD%'; for($i=0;$i -lt 60;$i++){try{Invoke-WebRequest -UseBasicParsing ($url+'/api/health') -TimeoutSec 2 ^| Out-Null; Start-Process $url; exit}catch{Start-Sleep -Seconds 1}}"

echo.
echo [START] Dashboard: %DASHBOARD%
echo [INFO]  Press Ctrl+C here to stop the backend.
echo.
cd /d "%BACKEND%"
"%PYTHON%" -m uvicorn app.main:app --reload --port 8000
exit /b %errorlevel%

:setup_failed
echo.
echo [ERROR] Python environment setup failed.
pause
exit /b 1
