param(
  [Parameter(Mandatory = $true)]
  [string]$SdkRoot
)

$ErrorActionPreference = "Stop"
$SdkRoot = [System.IO.Path]::GetFullPath($SdkRoot)
$SdkManager = Join-Path $SdkRoot "cmdline-tools\latest\bin\sdkmanager.bat"
$AvdManager = Join-Path $SdkRoot "cmdline-tools\latest\bin\avdmanager.bat"
$Emulator = Join-Path $SdkRoot "emulator\emulator.exe"

if (-not (Test-Path -LiteralPath $SdkManager)) { throw "sdkmanager was not found under $SdkRoot" }
if (-not (Test-Path -LiteralPath $AvdManager)) { throw "avdmanager was not found under $SdkRoot" }

& $SdkManager "--sdk_root=$SdkRoot" --install "platform-tools" "emulator" "system-images;android-35;google_apis;x86_64"
if ($LASTEXITCODE -ne 0) {
  throw "Android SDK installation failed. Open a terminal and run sdkmanager --licenses, then retry."
}

$Avds = if (Test-Path -LiteralPath $Emulator) { & $Emulator -list-avds } else { @() }
if ($Avds -notcontains "FraudSandbox") {
  "no" | & $AvdManager create avd -n "FraudSandbox" -k "system-images;android-35;google_apis;x86_64" -d "pixel_6" --force
  if ($LASTEXITCODE -ne 0) { throw "The FraudSandbox AVD could not be created." }
}
