# CLAUDE.md

Generative-AI platform for automated static analysis and risk scoring of fraudulent APKs
(banking-fraud triage). See `plan.md` for the full product vision and `.claude/skills/apk-fraud-analyzer/SKILL.md`
for the dev workflow.

## What's built (MVP — Phase 1 + 2)
- APK upload + hashing (SHA256/MD5) + metadata
- Static analysis via **androguard** (pure-Python, no Java deps): manifest, permissions,
  suspicious APIs, URL/IP/keyword IOCs, obfuscation signals
- Transparent rule-based **risk score** with per-reason breakdown
- Optional **VirusTotal** corroboration (`intel/virustotal.py`) — displayed separately
  and never changes the local score/verdict; silent no-op without `VT_API_KEY`
- **YARA** signature scanning (`analyzer/yara_scan.py` + `rules/android_fraud.yar`) and
  **MITRE ATT&CK** Mobile mapping (`analyzer/mitre.py`) — both offline
- **APKiD** packer/compiler/anti-analysis fingerprint (`intel/apkid_scan.py`)
- **ML classifier** (`ml/`) — permission RandomForest, hybrid score; `train.py --demo` or
  Drebin. Optional/no-op without `model.pkl`. Note: apkid pulls `yara-python-dex` which
  changes the yara string API — handled in `yara_scan._matched_identifiers()`
- **Gemini** report generation (executive summary, findings, recommendations) with a
  template fallback when no API key is set
- Certificate red-flags + exported-component attack surface; Base64/hex IOC decode; native `.so` string scan
- SQLite persistence, PDF export, IOC CSV/JSON export, sample-history UI, Dockerfile/compose
- Static single-page dashboard served by FastAPI (Tailwind + Chart.js via CDN)

## Run
```powershell
cd backend
uvicorn app.main:app --reload --port 8000   # after pip install -r requirements.txt
```
Dashboard: http://localhost:8000

## Dynamic analysis (Phase 3 — adb + Frida)
- `dynamic/` runs an APK in an **attached emulator**: install → launch (optionally under
  Frida) → capture logcat / granted perms / services / network → score → uninstall.
- Opt-in only, via `POST /api/dynamic`; never part of the static `/api/analyze` flow.
- adb auto-located from PATH or `ANDROID_HOME`. Frida tier needs `frida-server` running
  on the emulator (runner returns setup instructions if absent). Pure parsers in
  `dynamic/sandbox.py` are unit-testable without a device.

## Hard rules
- **The static pipeline never executes the APK.** Execution happens ONLY in the dynamic
  sandbox, only inside the user's emulator, only when explicitly triggered — never on the
  host. Use an isolated AVD for real malware.
- Analyzer code must be defensive — partial findings over crashes.
- Only extracted findings (never raw APK) go to the LLM.
- Risk scoring stays rule-based and explainable.
