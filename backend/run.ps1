# Always launches the server with the venv's Python (no activation needed).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "[ERROR] .venv not found. Create it first:" -ForegroundColor Red
    Write-Host "    python -m venv .venv"
    Write-Host "    .venv\Scripts\python.exe -m pip install -r requirements.txt"
    exit 1
}
& $py -m uvicorn app.main:app --reload --port 8000
