---
name: apk-fraud-analyzer
description: Develop, run, and extend the Generative-AI APK fraud analysis platform in this repo. Use when working on APK static analysis, risk scoring, Gemini report generation, the FastAPI backend, or the dashboard frontend.
---

# APK Fraud Analyzer — Dev Workflow

A platform that ingests a suspicious Android APK, runs **static analysis** (manifest,
permissions, suspicious APIs, IOCs, obfuscation), computes a **rule-based risk score**,
and uses **Gemini** to generate a human-readable investigation report.

## Architecture

```
frontend/index.html  ──HTTP──>  FastAPI (backend/app/main.py)
                                    │
                                    ├─ analyzer/static_analyzer.py   (androguard)
                                    │    ├─ permissions.py   dangerous-permission catalog + score
                                    │    ├─ api_patterns.py  suspicious API signatures
                                    │    ├─ iocs.py          URL / IP / keyword + Base64/hex decode
                                    │    ├─ cert_analysis.py signing-cert red-flags
                                    │    ├─ components.py     exported-component attack surface
                                    │    ├─ obfuscation.py   entropy / short-name / multi-dex
                                    │    ├─ yara_scan.py     YARA rules (rules/android_fraud.yar)
                                    │    └─ mitre.py         ATT&CK Mobile technique mapping
                                    ├─ analyzer/risk_scoring.py       (combines feature scores)
                                    ├─ intel/virustotal.py            (VT hash/domain corroboration, optional)
                                    ├─ intel/apkid_scan.py            (packer/compiler/anti-analysis fingerprint)
                                    ├─ ml/ (features, train, classifier) (permission RandomForest, optional)
                                    ├─ dynamic/ (adb, sandbox, frida_runner, frida_hooks.js)  (emulator runtime analysis)
                                    ├─ genai/gemini_client.py         (Gemini report, graceful fallback)
                                    ├─ db.py                          (SQLite, stdlib)
                                    └─ report.py                      (PDF via reportlab)
```

One FastAPI process serves both the JSON API **and** the static dashboard. No Node build step.

## Run it

```powershell
cd backend
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env          # then put GEMINI_API_KEY in .env
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000 — the dashboard is served from `/`.

- No `GEMINI_API_KEY`? The app still runs; `gemini_client.py` falls back to a
  deterministic template report. Static analysis + scoring never depend on the LLM.
- API docs at http://localhost:8000/docs.

## Test sample

`tools/make_test_apk.py` hand-encodes a **harmless** APK (binary AXML manifest + a
minimal string-only `classes.dex`, no Android SDK needed) that trips every detector and
scores 100/Critical. It is unsigned and has zero executable code — safe to analyze,
cannot install on a real device. Regenerate with:
`python tools/make_test_apk.py samples/test_fakebank.apk`. If you add a new detector,
extend `PERMISSIONS` / `DEX_STRINGS` there so the sample still covers it.

## Key conventions

- **Androguard is pure-Python** — chosen so there is no Java / apktool / JADX system
  dependency. `AnalyzeAPK` returns `(apk, dex_list, analysis)`.
- **Never execute the APK.** This is static analysis only. Dynamic sandboxing is a
  future phase and must run in an isolated VM (see plan.md §14).
- All analyzer functions must be **defensive**: a malformed/edge-case APK should
  degrade to partial findings, never crash the request.
- Risk scoring is **rule-based and transparent** — every point added has a labeled
  reason in `score_breakdown` so the report can explain itself.
- Send only **extracted findings** to Gemini, never the raw APK bytes.

## Scoring weights

Live in `analyzer/risk_scoring.py` (mirrors plan.md §7). Score capped at 100.
Severity: 0–20 Low, 21–40 Medium, 41–70 High, 71–100 Critical.

## Where to extend

- New suspicious API → add a signature tuple in `api_patterns.py`.
- New dangerous permission → add to the catalog in `permissions.py`.
- New IOC type → extend regexes in `iocs.py`.
- New YARA rule → add to `rules/android_fraud.yar` (set `meta.score` + `meta.attack`).
- New ATT&CK mapping → add a rule tuple in `mitre.py` `_RULES` (+ technique in `_TECHNIQUES`).
- Retrain ML → `python -m app.ml.train --demo` (synthetic) or `--data <drebin feature_vectors>
  --labels <sha256_family.csv>`. Model space is permission multi-hot only (the one feature
  Drebin and our extractor express identically — see `ml/features.py` docstring).

## Dynamic analysis (Phase 3)

`dynamic/` drives an attached Android emulator via adb. `POST /api/dynamic` (multipart
APK + `duration` + `use_frida`) installs → launches (under Frida if requested) → captures
logcat/perms/services/network → scores → uninstalls. `dynamic/sandbox.py` keeps `parse_*`
helpers pure so they're unit-testable without a device (see how they're tested with
synthetic logcat/dumpsys text). Frida tier needs `frida-server` on the emulator — the
runner returns push/run instructions if it's not reachable. `scripts/setup_sandbox.ps1`
automates the whole environment (create/boot FraudSandbox AVD, `adb root`, download +
push + run the matching frida-server). Device targeting is **strict**:
auto-run only ever uses the AVD named by `DEFAULT_SANDBOX_AVD` (env `SANDBOX_AVD`, default
`FraudSandbox`); `_preferred_serial` returns None for any other device so malware never
lands on the user's other emulators — a non-sandbox device must be chosen explicitly
(UI dropdown → `serial` form field). To test live: `emulator -avd FraudSandbox`, confirm
`/api/health` shows `dynamic.sandbox_present: true`, then run a *real* signed APK (the
synthetic `test_fakebank.apk` is unsigned and won't install/run).

**Validated live** against OpenCalculator on a FraudSandbox API-35 AVD (install→launch→
capture→uninstall, dynamic score 0 = correct for benign). Two API-35/Windows gotchas
fixed during that test: (1) `adb logcat -c` *hangs* on API 35 — capture uses
`logcat -d --pid=<pid>` + package-name filtering instead of clearing; (2) adb output must
be decoded utf-8/replace (Windows cp1252 default crashes on logcat bytes). If the
emulator crashes on cold boot, add `-gpu swiftshader_indirect`.

**Frida tier validated live.** Key gotchas (all handled): (1) **Pin `frida==16.7.19`** —
Frida 17 removed the global `Java` bridge that `frida_hooks.js` uses (`ReferenceError:
'Java' is not defined`); 16.x keeps it. frida-server on device must match the python
version + ABI and run **as root** (`adb root` first; google_apis image is rootable).
(2) Old samples (target < SDK 24) need `adb install --bypass-low-target-sdk-block`
(baked into `adb.install`). (3) frida-server binaries are cached on F: at `tools/frida/`
(gitignored). A benign idle app yields 0 hook events (correct); real captured events need
a sample that calls a hooked API and launches cleanly on the modern AVD.

**Robust activation** (`sandbox.activate` + `collect_triggers`): handles event-triggered /
no-launcher malware. Per run it: `adb root` (protected broadcasts need it), installs with
`--bypass-low-target-sdk-block`, relaxes background limits (`appops RUN_ANY_IN_BACKGROUND`
+ `deviceidle whitelist`), then fires ALL entry points — launcher activity, `am broadcast`
to each declared receiver with its actions + common triggers (BOOT_COMPLETED, USER_PRESENT,
SMS_RECEIVED, …), and `am start-foreground-service` for services. Validated on `.w.apk`
(a packed dropper, `com.uctsadtxasch.quyry`): no launcher icon, BOOT_COMPLETED **delivered
to its receiver**; its services are stubs (`Not found` / `app=null`) because the real code
is a DexClassLoader-loaded packed payload gated by anti-VM + a dead C2 — so static's
"Critical dropper" is the accurate verdict and dynamic stays low (honest, packed-payload
limit, not an engine bug). Android 15 still blocks some shell-started services even rooted.

**Consent auto-dismissal** (`sandbox.dismiss_consent_dialogs`): legacy apps (target < SDK
23) pop a modal `permissioncontroller/ReviewPermissionsActivity` that BLOCKS foreground
execution — the app stalls there and never runs. The sandbox now uses `uiautomator dump`
to find and tap the positive button ("Continue"/"Allow"/…) by its on-screen bounds, then
re-fires the entry points. Confirmed on `.w.apk`: before, the process never started
(pid None, dialog left stuck on screen); after, **consent dismissed → process runs (pid
present), ~209 log lines, screen returns to launcher cleanly**. **Anti-anti-VM + runtime unpacking** (`frida_antivm.js` + `frida_runner.run_unpack`,
used when `run_dynamic(use_frida=True)`): defeats emulator-evasion and forces packed
droppers to reveal themselves. It spoofs `Build.*`→Pixel, hides qemu/goldfish in
SystemProperties, fakes telephony IDs, hides emulator files; uses **spawn-gating** to
hook a no-launcher app before any code runs (handle empty `spawn.identifier` at gate
time by resolving `/proc/pid/cmdline` — this was the key to catching the spawn), with
attach-after-start fallback; and hooks `Cipher.doFinal`/`DexClassLoader` to dump the
decrypted payload + `URL`/`Runtime.exec` for C2. Captured C2 endpoints + payload dumps
feed the score (Runtime C2 contact +25, Payload unpacked +15).
**Proven on `.w.apk`** (packed no-launcher dropper): bypassed its anti-VM and extracted
the live C2 `http://drv.androidsecurityteam.club:10000/ast_3rd/mediation` — score 3
(couldn't run) → **44** with the C2 IOC that static never found. Emulator caveat: API-35
AVD is unstable under heavy install/root/gating cycling — wedges the `package` service
(`Can't find service: package`) and needs an `adb reboot` to recover; dumps cache to
`tools/frida/`+`tools/dumps/`.

## Dependency gotcha

`apkid` installs `yara-python-dex`, which shadows the `yara` module with an OLDER
string-match API (match.strings are `(offset, identifier, data)` tuples, not StringMatch
objects). `yara_scan._matched_identifiers()` handles both — don't use `s.identifier` directly.
- ML classifier / dynamic sandbox → new modules under `analyzer/`, wire into
  `static_analyzer.analyze()` result and `risk_scoring`.
