<#
.SYNOPSIS
  One-command setup for the dynamic-analysis sandbox.

  Boots the dedicated FraudSandbox AVD, roots it, and installs a matching frida-server
  so BOTH dynamic tiers (adb + Frida) are ready. Safe to re-run (idempotent).

.DESCRIPTION
  Steps:
    1. Locate the Android SDK (ANDROID_HOME / ANDROID_SDK_ROOT).
    2. Create the FraudSandbox AVD if it doesn't exist.
    3. Boot it (unless already running) and wait for full boot.
    4. adb root (the google_apis image is rootable).
    5. Detect the device ABI + the installed frida version, download the matching
       frida-server from GitHub, decompress it, push it, and start it.

.PARAMETER Avd
  AVD name to use (default: FraudSandbox).

.PARAMETER NoFrida
  Only boot the sandbox; skip the frida-server setup (adb tier only).

.PARAMETER Headless
  Boot the emulator with -no-window.

.EXAMPLE
  .\scripts\setup_sandbox.ps1
  .\scripts\setup_sandbox.ps1 -NoFrida -Headless
#>
param(
  [string]$Avd = "FraudSandbox",
  [switch]$NoFrida,
  [switch]$Headless
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$VenvPy = Join-Path $RepoRoot "backend\.venv\Scripts\python.exe"

function Info($m) { Write-Host "[setup] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[setup] $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[setup] ERROR: $m" -ForegroundColor Red; exit 1 }

# --- 1. Locate the SDK ---------------------------------------------------------
$Sdk = $env:ANDROID_HOME
if (-not $Sdk) { $Sdk = $env:ANDROID_SDK_ROOT }
if (-not $Sdk -or -not (Test-Path $Sdk)) { Die "ANDROID_HOME / ANDROID_SDK_ROOT not set or invalid." }

$Adb      = Join-Path $Sdk "platform-tools\adb.exe"
$Emulator = Join-Path $Sdk "emulator\emulator.exe"
$AvdMan   = Join-Path $Sdk "cmdline-tools\latest\bin\avdmanager.bat"
foreach ($t in @($Adb, $Emulator)) { if (-not (Test-Path $t)) { Die "Missing SDK tool: $t" } }
Info "SDK: $Sdk"

# --- 2. Create the AVD if missing ---------------------------------------------
$avds = & $Emulator -list-avds 2>$null
if ($avds -notcontains $Avd) {
  Warn "AVD '$Avd' not found - creating it (android-35 google_apis x86_64)..."
  if (-not (Test-Path $AvdMan)) { Die "avdmanager not found; create the AVD in Android Studio." }
  "no" | & $AvdMan create avd -n $Avd -k "system-images;android-35;google_apis;x86_64" -d pixel_6 --force
  Info "Created AVD '$Avd'."
} else {
  Info "AVD '$Avd' exists."
}

# --- helper: find the serial whose AVD name matches -------------------------
function Get-AvdSerial($name) {
  $lines = & $Adb devices 2>$null
  foreach ($l in $lines) {
    if ($l -match "^(emulator-\d+)\s+device") {
      $serial = $Matches[1]
      $n = (& $Adb -s $serial emu avd name 2>$null | Select-Object -First 1)
      if ($n) { $n = $n.Trim() }
      if ($n -eq $name) { return $serial }
    }
  }
  return $null
}

# --- 3. Boot the AVD if not already running -----------------------------------
$serial = Get-AvdSerial $Avd
if ($serial) {
  Info "$Avd already running ($serial)."
} else {
  Info "Booting $Avd ..."
  $emuArgs = @("-avd", $Avd, "-no-snapshot-load", "-no-audio", "-no-boot-anim")
  if ($Headless) { $emuArgs += "-no-window" }
  Start-Process -FilePath $Emulator -ArgumentList $emuArgs -WindowStyle Minimized

  Info "Waiting for device to appear..."
  & $Adb wait-for-device
  Info "Waiting for full boot (sys.boot_completed)..."
  for ($i = 0; $i -lt 120; $i++) {
    $b = (& $Adb shell getprop sys.boot_completed 2>$null)
    if ($b -and $b.Trim() -eq "1") { break }
    Start-Sleep -Seconds 2
  }
  $serial = Get-AvdSerial $Avd
  if (-not $serial) { Die "Emulator did not finish booting in time." }
  Info "$Avd booted ($serial)."
}

if ($NoFrida) {
  Info "Done (adb tier ready). Skipped frida-server (-NoFrida)."
  Info "Confirm: open /api/health -> dynamic.sandbox_present should be true."
  exit 0
}

# --- 4. Root the device -------------------------------------------------------
Info "Requesting root (adb root)..."
& $Adb -s $serial root | Out-Null
Start-Sleep -Seconds 3
& $Adb -s $serial wait-for-device

# --- 5. frida-server: detect version + ABI, download, push, run ---------------
$fridaVer = $null
if (Test-Path $VenvPy) {
  try { $fridaVer = (& $VenvPy -c "import frida; print(frida.__version__)").Trim() } catch {}
}
if (-not $fridaVer) { $fridaVer = "16.7.19"; Warn "Could not read frida version from venv; defaulting to the pinned version $fridaVer" }

$abi = (& $Adb -s $serial shell getprop ro.product.cpu.abi).Trim()
switch -Wildcard ($abi) {
  "arm64*"   { $fArch = "arm64" }
  "armeabi*" { $fArch = "arm" }
  "x86_64"   { $fArch = "x86_64" }
  "x86"      { $fArch = "x86" }
  default    { $fArch = "x86_64" }
}
Info "frida $fridaVer  |  device ABI $abi -> frida arch $fArch"

$asset   = "frida-server-$fridaVer-android-$fArch"
$url     = "https://github.com/frida/frida/releases/download/$fridaVer/$asset.xz"
# Cache on the project drive (F:), not %TEMP%.
$tmpDir  = Join-Path $RepoRoot "tools\frida"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$xzPath  = Join-Path $tmpDir "$asset.xz"
$binPath = Join-Path $tmpDir "frida-server-$fridaVer-$fArch"

if (-not (Test-Path $binPath)) {
  Info "Downloading $url ..."
  try { Invoke-WebRequest -Uri $url -OutFile $xzPath -UseBasicParsing }
  catch { Die "Download failed: $($_.Exception.Message)`nGrab it manually from https://github.com/frida/frida/releases" }

  Info "Decompressing (.xz)..."
  if (-not (Test-Path $VenvPy)) { Die "venv python not found at $VenvPy (needed to decompress .xz)." }
  # Write the decompressor to a temp .py file — passing a quoted Python one-liner via
  # PowerShell's native-arg quoting drops the inner quotes (PS 5.1 bug).
  $decomp = Join-Path $tmpDir "_decompress.py"
  Set-Content -Path $decomp -Encoding ASCII -Value @(
    "import lzma, sys",
    "open(sys.argv[2], 'wb').write(lzma.open(sys.argv[1]).read())"
  )
  & $VenvPy $decomp $xzPath $binPath
  if (-not (Test-Path $binPath)) { Die "Decompression failed." }
} else {
  Info "Reusing cached frida-server: $binPath"
}

# Push + run (kill any stale instance first).
$remote = "/data/local/tmp/frida-server"
& $Adb -s $serial shell "pkill -x frida-server" 2>$null | Out-Null
Info "Pushing frida-server to device..."
& $Adb -s $serial push $binPath $remote | Out-Null
& $Adb -s $serial shell "chmod 755 $remote"
Info "Starting frida-server..."
# Close every inherited descriptor before backgrounding. This lets the adb shell exit
# immediately while Android init adopts the server; no hidden Windows adb process is
# left owning Frida's lifecycle.
& $Adb -s $serial shell "nohup $remote >/dev/null 2>&1 </dev/null &"
Start-Sleep -Seconds 3

$running = & $Adb -s $serial shell "ps -A | grep frida-server" 2>$null
if ($running) {
  Info "frida-server is running."
} else {
  Warn "Could not confirm frida-server is running. Start it manually with:"
  Warn ("  {0} -s {1} shell {2}" -f $Adb, $serial, $remote)
}

Info "Sandbox ready (adb + Frida). Confirm at /api/health -> dynamic.sandbox_present:true, frida_available:true"
Info "Now upload a REAL signed APK in the dashboard and click 'Run in Emulator'."
