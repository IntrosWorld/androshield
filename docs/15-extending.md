# 15 — Extending the Platform

> Recipes for the eight changes you are most likely to make, each with the rule that
> governs it and the evidence a change requires.

---

## 0. The rules that apply to every change

1. **Visibility and scoring are separate.** Adding a finding to the report is cheap.
   Adding points to the score requires evidence.
2. **Weight changes need before/after metrics and named regression cases.** This is the
   Phase-2 release gate in [ROBUSTNESS_PLAN.md](../ROBUSTNESS_PLAN.md), and the reason
   every zero-weight entry in the codebase carries a comment.
3. **Test against the benign corpus, not just malware.** A change that raises malware
   scores and benign scores equally has improved nothing.
4. **Be defensive.** New stages degrade to a partial result; they never crash the request.
5. **Never widen what the LLM sees or can do without deliberate review.**

---

## 1. Add a dangerous permission

**File:** [`analyzer/permissions.py`](../backend/app/analyzer/permissions.py)

```python
DANGEROUS_PERMISSIONS = {
    ...
    "NEW_PERMISSION": (8, "Category", "Why this matters for fraud — one clear sentence"),
}
```

Weighting guidance:

| Range | Use for |
|---:|---|
| 15–20 | Fraud-defining capability (accessibility, SMS read, device admin) |
| 8–12 | Strongly fraud-relevant but with legitimate uses |
| 3–6 | Contextual — meaningful mainly through correlation |
| 1–2 | Report-only context |
| **0** | Common in benign apps; visible but never scored |

Before choosing a weight, ask: **how many of the six [pinned benign apps](13-evaluation-and-accuracy.md#5-the-pinned-benign-corpus)
request this permission?** If the answer is "several", the weight belongs at 0–3 and the
signal belongs in a correlation rule.

Then: map it in [`mitre.py`](../backend/app/analyzer/mitre.py) if it corresponds to a
technique; consider whether it completes an existing fraud chain in
[`risk_scoring.py`](../backend/app/analyzer/risk_scoring.py); run the benign corpus.

---

## 2. Add a suspicious API signature

**File:** [`analyzer/api_patterns.py`](../backend/app/analyzer/api_patterns.py)

```python
("Label", r"Lcom/example/Target;", r"specificMethod|otherMethod", 10, 3,
 "What this behaviour means in fraud terms"),
```

Fields: `(label, class_regex, method_regex, invoked_score, reference_score, behaviour)`.

Rules:

- **Match specific methods, not whole classes.** `DevicePolicyManager abuse` matches only
  the five high-impact methods; the class alone is used by every MDM-aware app.
- **Use `.*` for the method regex only for capability classes** where subclassing means
  there is no method to name (e.g. `AccessibilityService`).
- **`reference_score` should be 0** unless a class reference is genuinely useful without a
  recovered callsite — reflection-heavy paths, malformed DEX. Keep it well below the
  invoked score.
- **Consider library-context suppression.** If SDKs commonly use this API, add the label
  to the check in `_library_caller`-based suppression, as `DexClassLoader` and
  `PathClassLoader` do.

---

## 3. Add a YARA rule

**File:** [`rules/android_fraud.yar`](../backend/app/rules/android_fraud.yar)

```yara
rule New_Fraud_Pattern
{
    meta:
        description = "One clear sentence about the pattern"
        severity    = "high"
        attack      = "T1234"
        score       = "18"
    strings:
        $cap1 = "MANIFEST_PERMISSION:android.permission.RECEIVE_SMS"
        $api  = "Landroid/telephony/SmsManager;"
        $c2   = /https?:\/\/[a-z0-9.-]+\/gate\.php/
    condition:
        $cap1 and $api and $c2
}
```

Guidance:

- **Require a combination.** A single-string rule belongs in the IOC stage, not YARA.
  YARA's value here is encoding an analyst-verified *pattern*.
- **Use the `MANIFEST_PERMISSION:` prefix** for declared capabilities. Without it, a
  permission constant embedded in a dependency matches identically to a permission the app
  actually requests — see [04 §11](04-static-analysis-pipeline.md#11-stage-11--yara).
- **Score 10–25.** The category cap is 40, so two strong matches saturate it.
- **Fill in `attack`** so the technique reaches the report.

The scan target is DEX strings + native strings + namespaced permissions + package name.

---

## 4. Add a correlation rule

**File:** [`analyzer/risk_scoring.py`](../backend/app/analyzer/risk_scoring.py),
inside `compute_risk`.

```python
if "CAPABILITY_A" in perms and "ApiB" in invoked_apis:
    correlation_score += 8
    correlation_bits.append("capability A + observed behaviour B")
```

Checklist:

- **Prefer `invoked_apis` over `apis`.** A string-pool reference should not earn a
  correlation bonus; the two strongest existing chains require invoked evidence.
- **Both sides must be independently common but jointly rare.** That is what makes a
  chain discriminative rather than just additive.
- **Write the `correlation_bits` string for a human.** It appears verbatim in the report
  and the PDF.
- **Points: 5–10.** The category cap is 20.
- **Verify no benign corpus app completes the chain.**

---

## 5. Add a whole analyzer stage

1. Create `analyzer/new_stage.py` with a pure function returning
   `{"findings": [...], "score": int, ...}`.
2. Wire it into `static_analyzer.analyze()` after string collection, wrapped defensively.
3. If it scores, add a cap to `CATEGORY_CAPS` and a breakdown entry in `compute_risk`.
4. Surface it in [`gemini_client._findings_payload()`](../backend/app/genai/gemini_client.py)
   if the report should mention it.
5. Add an evidence `kind` in [`agent/evidence.py`](../backend/app/agent/evidence.py) and
   map it to a tool in [`agent/tools.py`](../backend/app/agent/tools.py).
6. Add a dashboard panel ([11 §8](11-frontend.md#8-extending-the-dashboard)) and a PDF
   section in [`report.py`](../backend/app/report.py).
7. If it is optional, add an availability flag to `/api/health`.
8. Add tests.

Template:

```python
def analyze_new_stage(apk, dex_strings):
    """One-line summary. Defensive: partial findings over crashes."""
    findings, score = [], 0
    try:
        ...
    except Exception:
        log.warning("new_stage partial failure", exc_info=True)
    return {"findings": findings, "score": min(score, CAP)}
```

---

## 6. Add an agent tool

**File:** [`agent/tools.py`](../backend/app/agent/tools.py)

```python
READ_TOOLS = {
    ...
    "inspect_new_thing": {"new_kind"},
}
```

and a description in `tool_specs()`.

Non-negotiable constraints:

- **Read-only.** No writes, no execution, no network, no filesystem.
- **Zero arguments** unless there is a compelling reason. Arguments are the injection
  surface; the toolbox is bound to one case at construction time precisely so the model
  never supplies an identifier.
- **Bounded results.** Route through `_result()`, which caps at 20 items / ~12 000
  characters.
- **If it proposes an action, it must not perform it.** Model it on
  `request_dynamic_analysis`: return `{"status": "approval_required", "executed": false}`.
- **The score invariant is absolute.** No tool may return anything that could be
  interpreted as changing a score.

Add a test in `backend/tests/test_agentic.py` asserting the tool is read-only and
correctly bounded.

---

## 7. Add an IOC extractor

**File:** [`analyzer/iocs.py`](../backend/app/analyzer/iocs.py)

```python
NEW_IOC_RE = re.compile(r"your-pattern")
# in extract_iocs():
for m in NEW_IOC_RE.findall(s):
    new_iocs.add(m)
```

Then add it to the return dict, to `counts`, to `_flatten_iocs()` in
[`main.py`](../backend/app/main.py) so it reaches the CSV/JSON export, and to the
dashboard/PDF IOC panels.

Two lessons already paid for, in blood:

- **Use word boundaries.** Substring matching found `upi` in "grouping" and "occupied".
- **Do not derive structured indicators from bare strings.** The domain regex matched Java
  package names because `.io`, `.app`, `.icu`, and `.cc` are real TLDs. Domains are now
  derived only from parsed URL hosts.

---

## 8. Change the risk model

The highest-scrutiny change in the codebase. Required process:

1. **Baseline.** Run the full benign corpus **and** the malware regression set. Record
   every score.
2. **Change one thing.**
3. **Re-run both sets.** Record every score again.
4. **Produce a before/after table** like the one in
   [13 §4.1](13-evaluation-and-accuracy.md#41-local-regression-set-4-samples).
5. **Name the regression cases** the change is meant to fix and the ones it must not
   break.
6. **Comment the rationale in the code.** Every unusual weight in this codebase has a
   comment explaining why; that is what makes the calibration auditable a year later.
7. Verify the invariant still holds: `sum(breakdown points) == risk_score` pre-clamp.

> The release gate, quoted: *"no detector-weight change without before/after metrics and
> named regression cases."*

---

## 9. Testing

```bash
cd backend && .venv\Scripts\python.exe -m pytest tests -q
```

| Change | Test it in |
|---|---|
| Permission / API / YARA / correlation | `tests/test_accuracy.py` |
| Agent tool / schema / budget | `tests/test_agentic.py` |
| Dynamic parser | `tests/test_dynamic_parsers.py` |
| ML feature / training | `tests/test_ml_training.py` |
| Evaluation harness | `tests/test_maldroid_evaluator.py` |

Write parsers as **pure functions over text** so they are testable without an emulator,
an APK, or a network — the pattern `dynamic/sandbox.py` follows throughout.

For end-to-end checks: `python tools/make_test_apk.py` generates a harmless synthetic
fraud fixture, and `backend/tools/smoke_agent.py` exercises the agent path.

---

## 10. Code conventions

| Convention | Example |
|---|---|
| Module docstring states purpose **and** safety posture | *"Defensive: partial findings over crashes."* |
| Unusual weights carry a `#` comment explaining why | The zero-weight permission entries |
| Suppression rules explain the false positive they fix | The domain-from-URL-only comment |
| Every score has a cap | `CATEGORY_CAPS` |
| Every external call has a timeout | adb, Ollama, VirusTotal |
| Every temp file has a `finally` cleanup | `main._spool_upload` |
| Every env-derived number is clamped | `_env_int(name, default, min, max)` |
| Untrusted text is escaped at every sink | `esc()`, `safeHttpUrl()`, PDF escaping |

---

**Next:** [16 — Glossary](16-glossary.md).
