# 10 — API Reference

Base URL: `http://localhost:8000`. Interactive OpenAPI docs: `/docs` (FastAPI built-in).

Source: [`backend/app/main.py`](../backend/app/main.py)

---

## Endpoint index

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Capability and configuration report |
| `GET` | `/api/agent/health` | Agent config **plus** a live provider probe |
| `POST` | `/api/analyze` | Static analysis of an uploaded APK |
| `POST` | `/api/agent/investigate/{sample_id}` | Run the bounded agent on a stored sample |
| `POST` | `/api/dynamic` | Emulator sandbox run (opt-in) |
| `GET` | `/api/samples` | Recent analysis history |
| `GET` | `/api/samples/{id}` | Full stored analysis + report |
| `GET` | `/api/samples/{id}/iocs.json` | IOC export (JSON) |
| `GET` | `/api/samples/{id}/iocs.csv` | IOC export (CSV download) |
| `GET` | `/api/samples/{id}/report.pdf` | PDF report download |
| `GET` | `/` | The dashboard (static mount, registered last) |

CORS: `GET` and `POST` only, `Content-Type` only, origins from `CORS_ORIGINS` (default
`http://localhost:8000,http://127.0.0.1:8000`).

---

## `GET /api/health`

Every optional subsystem reports its own availability. This endpoint is the first thing
to check when something behaves unexpectedly.

```json
{
  "status": "ok",
  "gemini_configured": false,
  "virustotal_configured": false,
  "apkid_available": true,
  "ml_model_loaded": false,
  "analyzer_ready": true,
  "dynamic": {"available": false, "reason": "...", "devices": []},
  "frida_available": true,
  "agentic": {
    "enabled": false, "auto_run": false, "provider": "ollama",
    "model": "qwen3:8b", "max_steps": 8, "max_tool_calls": 4,
    "policy_version": "agent-policy-v1"
  }
}
```

> **`analyzer_ready: false` is the single most common setup problem.** It means
> androguard is not importable in the interpreter running uvicorn — almost always
> because the server was started from global Python instead of `backend/.venv`. In that
> state `/api/analyze` returns `503` rather than a misleading clean result.

The agent block here uses `check_provider=False` — it reports **configuration** without
paying the latency of an Ollama round-trip.

---

## `GET /api/agent/health`

Same shape, plus a live `provider_health` probe:

```json
{
  "enabled": true, "provider": "ollama", "model": "qwen3:8b",
  "provider_health": {
    "available": true, "provider": "ollama", "model": "qwen3:8b",
    "installed_models": ["qwen3:8b", "llama3.1:8b"], "reason": null
  }
}
```

When the configured model is not installed, `available` is `false` and `reason` states
`model qwen3:8b is not installed` — diagnosable without reading server logs.

---

## `POST /api/analyze`

**Request** — `multipart/form-data`

| Field | Type | Required | Notes |
|---|---|---|---|
| `file` | file | yes | Must end in `.apk` |

**Behaviour.** Streams the upload in 1 MiB chunks into a temp file, aborting past
`MAX_UPLOAD_MB` (default 200). Runs the full static pipeline, optional VirusTotal
corroboration, optional inline agent investigation, and report generation. Persists the
result. Deletes the temp file on every exit path.

**Response `200`**

```json
{ "id": "a1b2c3d4e5f6", "analysis": { ... }, "report": { ... } }
```

**Errors**

| Code | Cause |
|---:|---|
| `400` | Not a `.apk` filename |
| `413` | Upload exceeded `MAX_UPLOAD_MB` |
| `503` | Static-analysis engine (androguard) unavailable |
| `500` | Unexpected analysis failure (logged with full traceback) |

Note that a *parse* failure is **not** a `500` — it returns `200` with
`analysis_quality: "failed"`, `risk_score: null`, and `severity: "Unknown"`. Only an
infrastructure failure is a 500.

---

### The `analysis` object

#### `file`
```json
{"filename": "suspect.apk", "file_size": 4823910,
 "sha256": "7c54...", "md5": "3f9a..."}
```

#### Quality and coverage
```json
{"valid_apk": true,
 "analysis_quality": "full",            // full | partial | failed
 "analysis_coverage": {"manifest": true, "dex_control_flow": true, "dex_strings": 18422},
 "errors": []}
```

#### `manifest`
```json
{"package_name": "com.example.bank", "app_name": "SecureBank",
 "version_name": "2.1.0", "version_code": "21", "min_sdk": "21", "target_sdk": "28",
 "main_activity": "com.example.bank.MainActivity",
 "activities": [...], "services": [...], "receivers": [...], "providers": [...],
 "counts": {"activities": 12, "services": 3, "receivers": 4, "providers": 1}}
```

#### `permissions`
```json
{"all_permissions": ["android.permission.INTERNET", "..."],
 "dangerous": [{"permission": "android.permission.READ_SMS", "name": "READ_SMS",
                "category": "SMS", "score": 15,
                "reason": "Can read SMS — classic OTP/2FA theft"}],
 "dangerous_count": 5}
```

#### `apis`
```json
{"suspicious_apis": [
   {"api": "AccessibilityService", "score": 18,
    "behaviour": "Accessibility automation — screen scraping / auto-click fraud",
    "evidence": "3 call site(s)", "evidence_type": "invoked", "confidence": "high",
    "callers": ["Lcom/example/bank/A11y;->onServiceConnected"],
    "library_context": false}],
 "count": 7, "invoked_count": 4, "reference_count": 3}
```

`evidence_type` is `invoked` (a callsite was recovered) or `reference` (descriptor in the
string pool only). See [04 §8](04-static-analysis-pipeline.md#8-stage-8--suspicious-api-detection).

#### `iocs`
```json
{"urls": [...], "ips": [...], "domains": [...],
 "suspicious_urls": [{"url": "http://panel.example.xyz/gate.php",
                      "reasons": ["higher-risk .xyz domain", "fraud/C2-like path", "cleartext HTTP"],
                      "score": 4, "confidence": "medium"}],
 "firebase_endpoints": [...], "telegram_tokens": [...], "hardcoded_secrets": [...],
 "suspicious_keywords": [{"keyword": "otp", "count": 14}],
 "financial_keywords": ["otp", "upi"],
 "decoded_blobs": 23, "native_strings_scanned": 1840,
 "counts": {"urls": 12, "ips": 2, "domains": 5, "suspicious_urls": 3,
            "telegram_tokens": 1, "secrets": 2, "keywords": 9,
            "financial_keywords": 2, "decoded_blobs": 23}}
```

#### `obfuscation`
```json
{"signals": [{"signal": "Heavy name obfuscation",
              "detail": "812/1043 classes have 1-2 char names (78%)", "score": 5}],
 "score": 13, "dex_count": 3, "native_libs": ["lib/arm64-v8a/libnative.so"],
 "high_entropy_count": 142, "high_entropy_ratio": 0.4721, "is_obfuscated": true}
```

#### `certificate` · `components`
```json
{"present": true, "flags": [{"flag": "Android debug certificate", "score": 6}], "score": 6}
{"exported": [{"type": "receiver", "name": ".SmsReceiver",
               "has_permission": false, "has_intent_filter": true}],
 "count": 5, "unguarded_count": 3, "score": 8}
```

#### `yara` · `apkid` · `mitre`
```json
{"available": true,
 "matches": [{"rule": "SMS_OTP_Stealer",
              "description": "Reads/intercepts SMS and has a network channel — OTP theft pattern",
              "severity": "high", "attack": "T1582", "score": 20,
              "matched_strings": ["$sms_read", "$http"]}],
 "score": 20}

{"available": true, "findings": [{"name": "Jiagu", "category": "Packer", "score": 15}], "score": 15}

{"techniques": [{"id": "T1582", "name": "SMS Control", "tactic": "Impact/Collection"}],
 "tactics": ["Impact/Collection", "Collection"], "count": 8}
```

#### `ml` · `virustotal`
```json
{"available": true, "malware_probability": 0.9134, "prediction": "flagged",
 "decision_threshold": 0.83, "confidence": 0.9134,
 "contributing_permissions": [{"permission": "RECEIVE_SMS", "importance": 0.081}],
 "model_metrics": {...}, "trained_at": "2026-03-11 09:22:14"}

{"queried": true,
 "file": {"found": true, "malicious": 34, "suspicious": 2, "undetected": 22,
          "threat_label": "trojan.banker/hydra",
          "permalink": "https://www.virustotal.com/gui/file/7c54..."},
 "flagged_domains": [{"domain": "panel.example.xyz", "malicious": 6}]}
```

#### Verdict block
```json
{"risk_score": 100, "severity": "Critical",
 "score_breakdown": [{"category": "Dangerous permissions", "points": 33,
                      "detail": "5 dangerous permission(s)"},
                     {"category": "YARA signatures", "points": 40,
                      "detail": "SMS_OTP_Stealer, Accessibility_Overlay_Trojan"}],
 "detected_behaviors": ["OTP / SMS theft", "Accessibility abuse (screen scraping / auto-click)"],
 "recommendations": ["Block the APK SHA256 hash across endpoints", "..."]}
```

**Invariant:** `sum(b.points for b in score_breakdown) == risk_score`, before the clamp
to 100.

#### `agentic`
```json
{"enabled": true, "status": "completed", "provider": "ollama", "model": "qwen3:8b",
 "policy_version": "agent-policy-v1", "steps_used": 5, "duration_ms": 18422,
 "hypotheses": [{"claim": "The application intercepts SMS and forwards content to a Telegram bot.",
                 "confidence": "high",
                 "evidence_ids": ["permission:READ_SMS", "ioc:telegram_token"]}],
 "gaps": ["No confirmation the payload URL is live."],
 "recommended_next_steps": ["Run isolated dynamic analysis to observe runtime exfiltration."],
 "audit": [{"step": 1, "action": "inspect_permissions", "status": "ok",
            "reason": "Need permission evidence", "executed": true,
            "evidence_ids": ["permission:READ_SMS"], "duration_ms": 812}]}
```

`status` ∈ `completed` · `unavailable` · `budget_exhausted` · `failed`.

---

### The `report` object

```json
{
  "executive_summary": "…2–4 sentences for a non-technical fraud manager…",
  "technical_summary": "…1–2 paragraphs correlating the evidence…",
  "threat_assessment": "Likely Malicious",
  "key_findings": ["…"],
  "attack_chain": ["Installed via sideload", "Requests accessibility", "…"],
  "recommended_actions": ["…"],
  "generated_by": "gemini-2.0-flash"
}
```

`threat_assessment` ∈ `No Strong Malicious Evidence` · `Suspicious` · `Likely Malicious` ·
`Confirmed Malicious`. `generated_by` is `"template-fallback"` when no model was used.

---

## `POST /api/agent/investigate/{sample_id}`

Runs the bounded agent over a **stored** sample. Reads saved evidence from SQLite;
**never reopens the APK** (which was deleted at the end of the original request).

**Response `200`**
```json
{"id": "a1b2c3d4e5f6", "agentic": {...}, "report": {...}}
```

Both the updated analysis and the regenerated report are persisted.

**Errors**

| Code | Cause |
|---:|---|
| `409` | `AGENT_ENABLED` is false |
| `404` | Sample not found (or deleted mid-request) |
| `409` | Sample has no completed static findings (`valid_apk` false or `risk_score` null) |
| `500` | **Agent scoring invariant failed** — logged at `CRITICAL`; see [07 §8](07-agentic-investigation.md#8-the-score-invariant--four-independent-enforcements) |

---

## `POST /api/dynamic`

> ⚠️ **This endpoint installs and runs the APK inside an attached emulator.** Read
> [09 — Dynamic Analysis](09-dynamic-analysis.md) before enabling it, and use an isolated
> AVD for real malware.

**Request** — `multipart/form-data`

| Field | Type | Default | Notes |
|---|---|---|---|
| `file` | file | — | Must end in `.apk` |
| `duration` | int | 15 | Observation seconds, clamped 5–120 |
| `use_frida` | bool | false | Frida hooking tier |
| `serial` | str | none | Explicit device; must be currently connected |

Without `serial`, the runner targets **only** the AVD named by `SANDBOX_AVD` (default
`FraudSandbox`) — never an arbitrary attached device.

**Errors:** `400` (bad extension, unconnected serial, unreadable package),
`503` (no emulator available — with the reason), `500` (unexpected failure).

Response shape: [09 §9](09-dynamic-analysis.md#9-result-shape).

---

## History and exports

### `GET /api/samples`

```json
{"samples": [{"id": "a1b2c3d4e5f6", "filename": "suspect.apk", "sha256": "7c54...",
              "package_name": "com.example.bank", "risk_score": 100,
              "severity": "Critical", "upload_time": 1771234567.89}]}
```

Most recent first, limit 50.

### `GET /api/samples/{id}`

The full stored row: scalar columns plus the complete `analysis` and `report` objects.
`404` if unknown.

### `GET /api/samples/{id}/iocs.json`

```json
{"sample_id": "a1b2c3d4e5f6", "package": "com.example.bank", "sha256": "7c54...",
 "iocs": [{"type": "url", "value": "http://panel.example.xyz/gate.php"},
          {"type": "telegram_token", "value": "..."},
          {"type": "sha256", "value": "7c54..."},
          {"type": "package", "value": "com.example.bank"},
          {"type": "vt_flagged_domain", "value": "panel.example.xyz"}]}
```

Types: `url`, `domain`, `ip`, `telegram_token`, `secret`, `firebase`, `sha256`, `md5`,
`package`, `vt_flagged_domain`. Empty values are dropped.

### `GET /api/samples/{id}/iocs.csv`

Same rows as `type,value`, with `"` doubled per RFC 4180. Downloads as
`<package_name>_iocs.csv`.

### `GET /api/samples/{id}/report.pdf`

ReportLab-rendered PDF containing: metadata and score header, executive and technical
summaries, detected behaviours, attack chain, **full score breakdown**, technical
evidence, IOCs, YARA matches, MITRE mapping, certificate and attack surface, APKiD, ML
verdict, VirusTotal, the agentic investigation, and recommendations. Downloads as
`<package_name>_report.pdf`.

---

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `GEMINI_API_KEY` | — | Enables model-written reports; absent ⇒ template fallback |
| `GEMINI_MODEL` | `gemini-2.0-flash` | Report + optional agent provider model |
| `VT_API_KEY` | — | Enables VirusTotal corroboration; absent ⇒ silent no-op |
| `MAX_UPLOAD_MB` | `200` | Hard upload limit (`413` past it) |
| `CORS_ORIGINS` | localhost:8000 pair | Comma-separated allowed origins |
| `SANDBOX_AVD` | `FraudSandbox` | AVD name for dynamic auto-selection |
| `AGENT_ENABLED` | `false` | Master agent switch |
| `AGENT_AUTO_RUN` | `false` | Run the agent inline during `/api/analyze` |
| `AGENT_PROVIDER` | `ollama` | `ollama` \| `gemini` |
| `AGENT_MAX_STEPS` | `8` | Clamped 1–20 |
| `AGENT_MAX_TOOL_CALLS` | `4` | Clamped 1–19 and ≤ steps−1 |
| `AGENT_TIME_BUDGET_SECONDS` | `420` | Clamped 1–3600 |
| `AGENT_PROVIDER_TIMEOUT_SECONDS` | `240` | Clamped 5–900 |
| `AGENT_CONTEXT_TOKENS` | `4096` | Clamped 2048–32768 |
| `AGENT_MAX_INVALID_ACTIONS` | `2` | Clamped 1–5 |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Local provider endpoint |
| `OLLAMA_MODEL` | `qwen3:8b` | Local planner model |
| `AGENT_GEMINI_REVIEW` | `false` | Optional cloud critique of local hypotheses |

---

**Next:** [11 — Frontend](11-frontend.md).
