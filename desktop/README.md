# APK Fraud Analyzer Desktop

Electron (Chromium + Node.js) hosts the existing dashboard with a managed Python/FastAPI
engine. The web app remains available separately. The desktop build includes local
Tailwind CSS, Chart.js, fonts, and icons; no CDN is needed to load the interface.

## Develop on Windows

From the repository root:

```powershell
python -m venv backend/.venv
backend/.venv/Scripts/python -m pip install -r backend/requirements.txt
cd desktop
npm ci
npm start
```

If the backend environment already exists, reuse it. Node.js 22 or newer is required
for development (minimum 22.12). Set `APK_DESKTOP_PYTHON` to an absolute interpreter path to override
automatic `backend/.venv` detection. On macOS/Linux, use `backend/.venv/bin/python`.

The application provides native menus, Ctrl/Cmd+O to select an APK, zoom controls,
native export save dialogs, and a single running instance. External links require
confirmation before opening in the system browser because extracted IOCs can point
to malicious sites. Selecting an APK does not analyze or execute it automatically.

## Local state and process lifecycle

History and settings use a separate SQLite database under Electron's `userData`
directory (normally `%APPDATA%/APK Fraud Analyzer` on Windows). Use **Help → Open data
folder** to locate it. Web history is not copied automatically. Desktop Frida downloads
and runtime dumps also go under this writable directory. `APK_DESKTOP_USER_DATA` can
override the directory for isolated tests. Saved API keys use the existing settings
store; this version does not add OS keychain encryption.

The backend binds only to `127.0.0.1` on an OS-assigned port, requires a random token
provided privately by Electron, and exits when the parent pipe closes. Shutdown allows
eight seconds to drain work, then terminates the owned process tree. Interrupted jobs
are recovered using the existing backend startup behavior. Closing the last window
quits the app on every platform. A failed engine startup shows a diagnostic dialog;
restart after fixing the reported dependency problem.

The renderer has no Node.js access, uses Chromium sandboxing and context isolation,
rejects browser permissions, and loads scripts only from the bundled app. The normal
web server does not inherit the desktop authentication wrapper.

Analysis remains static by default. Runtime analysis still requires an explicit action
and an attached emulator; no desktop launch or test executes an APK. Optional Gemini,
VirusTotal, Ollama, SDK, Frida-server and model capabilities retain their existing setup
requirements. Development honors `backend/.env`; packaged apps do not include it.
Configure provider keys in Settings or the launch environment. No APKs, models,
databases, developer secrets, or Android SDK are included in the distribution.

## Verify

```powershell
npm run assets
npm test
npm run smoke
```

Tests cover authentication rejection, persistence across backend restarts, process
shutdown and navigation/export policy. The Electron smoke test uses the harmless,
non-executable generated APK, checks engine readiness, performs static analysis, and
checks PDF/IOC endpoints, a native PDF download, and theme persistence. It writes
`build/desktop-smoke.png` and uses a temporary
profile so existing history is untouched.

## Package

### Portable Windows app

Run `npm run portable` to create `dist/APK-Fraud-Analyzer-Portable-0.1.0.exe`.
Double-click it from a writable folder or USB drive; no installer, administrator
rights, Python, or Node.js installation is required. History, settings, provider
keys, theme, and browser profile live in **APK Fraud Analyzer Data** beside the EXE.
Move that folder together with the EXE to retain your workspace. Existing installed
app history is not copied automatically. Close the app before moving it or ejecting
the drive. Optional Android SDK/emulator and Ollama installations remain external.

The launcher extracts its runtime to a unique Windows temporary folder at each
launch and cleans that runtime up on normal exit. Startup can take longer than the
installed version and requires roughly 1 GB of free temporary space. The build also
produces **Run Portable.cmd**: keep it beside the EXE and double-click it to put
temporary runtime files on the portable drive instead of the Windows system drive.
This is useful when C: is low on space and does not change global Windows settings.
This is an unsigned Windows x64 build. To verify the actual
portable launcher, set `APK_DESKTOP_EXECUTABLE` to its full path and
then run `node scripts/smoke-portable.cjs`. The test copies the
launcher into `build/portable-tests` and verifies analysis, exports, and persistence
across relaunch without touching your data.

### Installed app

Install the build dependency into the same backend environment, then build:

```powershell
# From the repository root
backend/.venv/Scripts/python -m pip install -r desktop/requirements-build.txt
cd desktop
npm run pack  # unpacked app in dist/win-unpacked
npm run dist  # Windows NSIS installer in dist
```

PyInstaller bundles the Python runtime and analyzer dependencies; recipients do not
need Python or Node installed. Electron Builder packages only explicitly listed
desktop code and generated resources. Build on each target OS: Windows produces NSIS,
macOS DMG, and Linux AppImage. Only Windows is validated here. Release signing,
notarization and auto-updates are not configured; Windows builds are unsigned.

To smoke-test an unpacked Windows build:

```powershell
$env:APK_DESKTOP_EXECUTABLE = (Resolve-Path 'dist/win-unpacked/APK Fraud Analyzer.exe').Path
node scripts/smoke.cjs
Remove-Item Env:APK_DESKTOP_EXECUTABLE
```

The build currently uses Tailwind 3 to match the existing dashboard. `npm audit` reports
transitive build-tool advisories (pattern/selector parsing and logging). These development
dependencies are not shipped as application JavaScript; upgrading to Tailwind 4 needs a
separate stylesheet compatibility pass. Use trusted repository content for builds.
