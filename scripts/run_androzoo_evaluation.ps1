param(
    [int]$Benign = 20,
    [int]$Malicious = 20,
    [int]$Workers = 4
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$Python = Join-Path $RepoRoot "backend\.venv\Scripts\python.exe"
$Tool = Join-Path $RepoRoot "backend\tools\androzoo_pipeline.py"
$DataDir = Join-Path $RepoRoot "test\androzoo"
$Metadata = Join-Path $DataDir "latest.csv.gz"
$Manifest = Join-Path $DataDir "evaluation-manifest.csv"
$ApkDir = Join-Path $DataDir "apks"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Backend virtual environment not found: $Python"
}
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

& $Python -u $Tool key-status
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -u $Tool fetch-metadata --output $Metadata
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -u $Tool select --metadata $Metadata --manifest $Manifest `
    --benign $Benign --malicious $Malicious
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -u $Tool download --manifest $Manifest --output $ApkDir --workers $Workers
exit $LASTEXITCODE
