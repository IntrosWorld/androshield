# 12 — Deployment and Operations

---

## 1. Local setup (Windows / PowerShell)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env      # optional — the platform runs fully without any keys

# Start the server using the venv's Python explicitly:
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Or simply:

```powershell
.\run.ps1
```

```bat
run.bat
```

Both wrappers exist for one reason, and it is the most common failure in the project.

### ⚠️ The venv trap

`Activate.ps1` only works in **PowerShell**. In `cmd.exe` it silently does nothing, so
`uvicorn` resolves to global Python — which has no androguard. The server starts fine and
every analysis fails.

The platform is built to catch this rather than mislead you:

| Layer | Behaviour |
|---|---|
| Startup | `log.error("androguard is NOT importable in this interpreter — analysis will fail…")` |
| `/api/health` | `"analyzer_ready": false` |
| `/api/analyze` | `503` with a remediation message — **never** a clean result |
| Dashboard | Red **"Engine offline"** badge |

Always confirm `analyzer_ready: true` before trusting any result:

```bash
curl http://localhost:8000/api/health
```

Then open **http://localhost:8000**.

---

## 2. Linux / macOS

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

---

## 3. Docker

```bash
docker compose up --build
```

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt   # deps first — layer caching
COPY backend ./backend
COPY frontend ./frontend
WORKDIR /app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Every dependency ships manylinux wheels, so **no compiler is needed in the image** — a
direct consequence of the pure-Python androguard choice.

`docker-compose.yml` passes `GEMINI_API_KEY`, `GEMINI_MODEL`, and `VT_API_KEY` through
from the shell (all optional) and mounts `./backend/data` so the SQLite history survives
container restarts.

Notes:

- The **static** pipeline is safe to containerise — it never executes the APK.
- The **dynamic** sandbox is not covered by this image; it needs an emulator and adb on
  the host.

---

## 4. Configuration

Copy `backend/.env.example` → `backend/.env`. Every variable is optional; the platform
runs with an empty file. `.env` is git-ignored.

```bash
# ── Report generation ────────────────────────────────────────────
GEMINI_API_KEY=                      # absent ⇒ deterministic template reports
GEMINI_MODEL=gemini-2.0-flash

# ── Threat intelligence ──────────────────────────────────────────
VT_API_KEY=                          # free tier: 4 req/min, 500/day

# ── Request hardening ────────────────────────────────────────────
MAX_UPLOAD_MB=200
CORS_ORIGINS=http://localhost:8000,http://127.0.0.1:8000

# ── Bounded agentic investigation (off by default) ───────────────
AGENT_ENABLED=false
AGENT_WORKFLOW_ENABLED=false
AGENT_AUTO_RUN=false
AGENT_PROVIDER=ollama
AGENT_MAX_STEPS=8
AGENT_MAX_TOOL_CALLS=4
AGENT_TIME_BUDGET_SECONDS=420
AGENT_PROVIDER_TIMEOUT_SECONDS=240
AGENT_CONTEXT_TOKENS=4096
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen3:8b
AGENT_GEMINI_REVIEW=false
```

`load_dotenv()` resolves `backend/.env` relative to `main.py`, so uvicorn can be launched
from any working directory.

---

## 5. Optional subsystems

| Subsystem | To enable | Verify at `/api/health` |
|---|---|---|
| Gemini reports | Set `GEMINI_API_KEY` | `gemini_configured: true` |
| VirusTotal | Set `VT_API_KEY` | `virustotal_configured: true` |
| YARA | Installed with requirements | matches appear in results |
| APKiD | Installed with requirements | `apkid_available: true` |
| ML classifier | Train a `model.pkl` ([08](08-ml-classifier.md)) | `ml_model_loaded: true` |
| Agent | `AGENT_ENABLED=true` + a running Ollama with the model pulled | `/api/agent/health` |
| Guided workflow | `AGENT_ENABLED=true` + `AGENT_WORKFLOW_ENABLED=true` + sandbox AVD | `agentic_workflow.enabled` in `/api/health` |
| Dynamic | Start the sandbox AVD ([09](09-dynamic-analysis.md)) | `dynamic.available: true` |
| Frida | `frida-server` running on the emulator | `frida_available: true` |

### Agent quickstart

```bash
ollama pull qwen3:8b
ollama serve
# then in backend/.env:  AGENT_ENABLED=true
curl http://localhost:8000/api/agent/health
python backend/tools/smoke_agent.py
```

---

## 6. Test data

No APK to hand? Generate a **harmless synthetic fixture** that declares dangerous
permissions and embeds fraud-like strings without any malicious code:

```bash
python tools/make_test_apk.py
```

For real-world calibration, use the pinned benign controls in
[TEST_CORPUS.md](../TEST_CORPUS.md) — Fossify Calculator, Aegis, KeePassDX, Material
Files, NewPipe, OWASP UnCrackable — each with a published SHA-256 to verify before
analysis.

---

## 7. Tests

```bash
cd backend
.venv\Scripts\python.exe -m pytest tests -q
```

| File | Covers |
|---|---|
| `test_accuracy.py` | API evidence typing, IOC extraction, risk fusion, verdict policy, upload bounds, PDF generation |
| `test_agentic.py` | Evidence graph bounding, tool allowlisting, schema validation, budgets, score invariant |
| `test_dynamic_parsers.py` | All `parse_*` functions and sandbox device selection — **no emulator required** |
| `test_ml_training.py` | Vocabulary, split, threshold selection, bundle shape |
| `test_maldroid_evaluator.py`, `test_maldroid_archive_sampler.py` | Evaluation harness and bounded archive sampling |

The suite runs in seconds and needs no network, no device, and no API keys.

---

## 8. Performance

| Phase | Typical | Notes |
|---|---|---|
| Hashing | <1 s | Streamed, 1 MiB blocks |
| `AnalyzeAPK` | 2–30 s | **Dominates.** Scales with DEX size and class count |
| String collection | 1–5 s | Bounded by explicit caps |
| Analyzer stages | <1 s each | Pure computation over collected strings |
| YARA | <1 s | Rules compiled once and cached |
| APKiD | 1–5 s | Its own YARA pass over the archive |
| VirusTotal | 1–3 s | Network; skipped without a key |
| Gemini | 2–10 s | Network; skipped without a key |
| Agent | 10–120 s | Local model; bounded by the step/time budgets |

Tuning notes: reduce `MAX_UPLOAD_MB` to reject huge samples earlier; keep
`AGENT_AUTO_RUN=false` so interactive analyses stay fast and investigations are explicit.
`STATIC_ANALYSIS_CONCURRENCY` bounds CPU-heavy pipelines per server process (default 2),
and `STATIC_ANALYSIS_QUEUE_LIMIT` rejects excess work instead of allowing unbounded
temporary uploads. Emulator analysis is serialized because one AVD cannot safely run two
malware samples at once.

Set `DATABASE_URL` to use PostgreSQL/Neon; otherwise SQLite remains the automatic local
fallback. PostgreSQL uses pooled, pre-pinged connections and an advisory transaction lock
to make analysis queue admission atomic across API processes. SQLite retains WAL mode and
a five-second busy timeout. Both backends keep indexes, bounded pagination, analysis jobs,
and Agentic Investigation progress. A new API worker recovers only stale job leases, so it
does not fail work still running in another process.

PostgreSQL removes the single-writer database bottleneck, but the analysis semaphore is
still process-local. Before horizontally scaling API replicas, move execution to a real
worker queue (Redis/Celery, Dramatiq, or equivalent); PostgreSQL remains the source of
truth for job state, not the task broker.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `analyzer_ready: false`, "Engine offline" | uvicorn running under the wrong Python | Start via `run.bat` / `run.ps1`, or `.venv\Scripts\python.exe -m uvicorn …` |
| `503` on analyze | Same | Same |
| Report reads generically | No `GEMINI_API_KEY` | Set it, or accept the template fallback |
| No VirusTotal panel | No `VT_API_KEY` | Set it (free tier: 4 req/min) |
| `413` | File over `MAX_UPLOAD_MB` | Raise the limit or use a smaller sample |
| YARA import/string errors | `apkid` pulls `yara-python-dex`, changing the string API | Already handled in `_matched_identifiers()`; reinstall requirements if it recurs |
| `dynamic.available: false` | Sandbox AVD not running | `emulator -avd FraudSandbox`, or pass an explicit `serial` |
| Frida setup instructions returned | `frida-server` not running on the device | Push and run a matching `frida-server`; keep frida pinned at 16.x |
| Agent `unavailable` | Ollama down, or model not pulled | `ollama serve`; `ollama pull qwen3:8b`; check `/api/agent/health` → `installed_models` |
| Agent `budget_exhausted` | Model too slow or too indecisive | Raise `AGENT_TIME_BUDGET_SECONDS`, or use a smaller/faster model |
| `500 Agent scoring invariant failed` | The agent tried to mutate scoring state | **Treat as a bug.** Logged at `CRITICAL`. Do not work around it — see [07 §8](07-agentic-investigation.md#8-the-score-invariant--four-independent-enforcements) |
| Unicode crash in dynamic runs | Windows cp1252 vs logcat bytes | Already fixed: adb calls force `utf-8` + `errors="replace"` |

---

## 10. Production considerations

This is a hackathon/triage platform. Before any real deployment:

| Area | Required change |
|---|---|
| **Authentication** | There is none. Add auth before exposing it beyond localhost. |
| **Database** | Use PostgreSQL via `DATABASE_URL` for concurrent analysts. SQLite is intended only for local/single-user mode. |
| **Sample storage** | APKs are deleted after analysis. If you need retention, store them encrypted, access-controlled, and clearly marked. |
| **Rate limiting** | None. Analysis is CPU-expensive and trivially abusable. |
| **CORS** | Keep it restricted; the permissive default is for localhost development. |
| **Secrets** | `.env` is fine locally; use a real secrets manager in production. |
| **Dynamic isolation** | Emulator on an isolated network segment, cold snapshot restored between samples, never on an analyst workstation. |
| **Logging** | `log.exception` may include exception text derived from a sample. Review before shipping logs to a central store. |

---

**Next:** [13 — Evaluation & Accuracy](13-evaluation-and-accuracy.md).
