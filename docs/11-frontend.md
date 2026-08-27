# 11 — The Dashboard

> A single-page app with no build step, no framework, and no `npm install` — served by
> the same process that runs the API.

Sources: [`frontend/index.html`](../frontend/index.html), [`frontend/app.js`](../frontend/app.js)

---

## 1. Why there is no build step

```python
# main.py — mounted LAST so /api/* always takes priority
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
```

Two files (`index.html`, `app.js`), Tailwind and Chart.js from CDN, vanilla ES6. The
entire deployment story is:

```bash
uvicorn app.main:app --port 8000     # → API and dashboard both live
```

For a security triage tool that a reviewer, an auditor, or a fraud analyst must be able
to stand up in one command, that reproducibility is worth more than the ergonomics of a
component framework. There is no `node_modules`, no bundler version to pin, and no build
that can break independently of the backend.

**Mount ordering matters:** the static mount at `/` is registered *after* every `/api/*`
route, so route resolution never shadows the API.

---

## 2. Layout

```
┌─────────────────────────────────────────────────────────────┐
│ APK Fraud Analyzer                        [engine badge]    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌───────────────────────────────────────────────────┐     │
│   │  Drop a suspicious .apk here or click to browse    │     │
│   │  Static analysis only — the APK is never executed. │     │
│   └───────────────────────────────────────────────────┘     │
│                    [ Analyze APK ]                          │
├─────────────────────────────────────────────────────────────┤
│ Recent Analyses                                             │
│  ● Critical  100  com.example.bank      2 minutes ago       │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐   Executive summary                           │
│  │  GAUGE   │   Threat assessment · package · SHA-256       │
│  │   100    │   Detected behaviours (chips)                 │
│  │ Critical │                                               │
│  └──────────┘                                               │
├──────────────────────────┬──────────────────────────────────┤
│ Score breakdown (chart)  │ Dangerous permissions            │
├──────────────────────────┼──────────────────────────────────┤
│ Suspicious APIs          │ Network indicators / IOCs        │
├──────────────────────────┼──────────────────────────────────┤
│ YARA · APKiD · MITRE     │ Certificate · attack surface     │
├──────────────────────────┼──────────────────────────────────┤
│ ML verdict · VirusTotal  │ Agentic investigation + audit    │
├──────────────────────────┴──────────────────────────────────┤
│ Attack chain · Recommendations                              │
│ [ Download PDF ] [ IOCs CSV ] [ IOCs JSON ] [ Investigate ] │
├─────────────────────────────────────────────────────────────┤
│ Dynamic analysis (emulator)   [device] [duration] [Frida]   │
└─────────────────────────────────────────────────────────────┘
```

A dark, glass-panel aesthetic (`.glass` = translucent white on `#0b1020`) chosen because
this is a tool people stare at for hours.

---

## 3. XSS: the threat that is easy to miss

**Every string the dashboard renders originates in an attacker-controlled file.** App
names, package names, URLs, certificate subjects, YARA matched strings, agent claims —
all of it comes from the APK. A package name can be
`<img src=x onerror=alert(document.cookie)>`.

Two primitives guard against this:

```javascript
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, ch => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[ch]));

const safeHttpUrl = (value) => { /* returns the URL only if scheme is http/https */ };
```

Rules applied throughout `render()`:

- **Every interpolated value passes through `esc()`.** No exceptions for "internal"
  fields — the score breakdown's `detail` string embeds extracted YARA rule names and
  URL fragments.
- **Every href passes through `safeHttpUrl()`.** This blocks `javascript:` and `data:`
  URIs harvested from the DEX string pool, which would otherwise become clickable
  script-execution links in the IOC panel.
- **`textContent` for error messages**, never `innerHTML`.

The same discipline applies on the server side in the PDF renderer, where untrusted
content is escaped before being handed to ReportLab's markup-aware paragraph parser.

---

## 4. Rendering model

`render(analysis, report)` rebuilds panels from the response. Panels are conditionally
hidden when their evidence is absent — no ML model means no ML panel — so the dashboard
never shows an empty card implying a subsystem ran and found nothing when it simply did
not run.

Severity colour is a single source of truth:

```javascript
const SEV_COLORS = { Low: …, Medium: …, High: …, Critical: …, Unknown: … };
```

used identically by the gauge, the history chips, and the panel accents.

### The gauge

A Chart.js doughnut with a centred score, coloured by severity. Deliberately shows
`risk_score` **and** the severity word: the number invites comparison between samples,
the word carries the operational meaning. When `risk_score` is `null` the gauge renders
`Unknown` in grey — visually distinct from Low, because
[conflating those two is the worst possible failure](04-static-analysis-pipeline.md#3-the-degradation-ladder).

### Score-breakdown chart

A horizontal bar chart of `score_breakdown`, one bar per category with its point value —
the visual form of the explainability contract. An analyst can see at a glance whether a
score of 72 came from one YARA hit or from eight small accumulations.

---

## 5. Health badges

`refreshHealth()` polls `/api/health` and reflects capability into the header:

| Condition | Display |
|---|---|
| `analyzer_ready: false` | Red **"Engine offline"** — androguard missing from the server's interpreter |
| `gemini_configured: false` | Report is marked template-generated |
| `ml_model_loaded`, `apkid_available`, `virustotal_configured` | Panel presence |
| `dynamic.available` | Enables/disables the dynamic section; `updateEmuStatus()` populates the device selector |
| `agentic.enabled` | Shows the Investigate control |

This is the design principle from [03](03-architecture.md) surfacing in the UI: **optional
layers are visibly optional.** The analyst is never left guessing whether an empty
VirusTotal panel means "clean" or "no API key" — the badge says which.

---

## 6. Interactions

| Action | Call | Result |
|---|---|---|
| Drop / browse a file | — | `setFile()` validates `.apk`, enables the button |
| Analyze | `POST /api/analysis-jobs`, then poll job | Phase-aware loading state → stored sample → history refresh |
| Click a history row | `GET /api/samples/{id}` | Re-renders the stored result |
| Download PDF / CSV / JSON | `GET …/report.pdf`, `…/iocs.csv`, `…/iocs.json` | Browser download |
| Run AI Review | `POST /api/agent/investigate/{id}` | `renderAgent()` with grounded hypotheses + audit |
| Start Agentic Investigation | `POST /api/agent/workflow/{id}` | Approval-controlled sandbox proposal and observations |
| Run manual sandbox | `POST /api/dynamic` | `renderDynamic()` with runtime findings and a hash-linked final score |

Errors surface in a dedicated error box via `showError()` / `hideError()` using
`textContent`, so a server error message containing attacker-derived text cannot inject
markup.

---

## 7. Review and investigation hierarchy

The results page deliberately separates three capabilities:

1. **AI Review** explains already-extracted evidence and never changes the score or
   executes the APK. It shows the three leading hypotheses first; remaining hypotheses,
   evidence gaps, grounding review, and action audit are available under **View full AI
   Review**.
2. **Agentic Investigation** is the primary runtime workflow. It proposes bounded
   sandbox actions, pauses for approval, observes the result, and decides whether another
   allowlisted action is justified.
3. **Manual Sandbox** is an advanced override for analysts who need a specific repeatable
   emulator configuration. It is collapsed by default so it does not compete with the
   guided workflow.

The action plan appears before advanced tools, and recent-analysis rows include both the
package and analysis time so repeated filenames remain distinguishable.

When an AI Review exists, the panel renders:

- **Hypotheses** — claim, a confidence chip (`low`/`medium`/`high`), and the cited
  evidence IDs.
- **Evidence gaps** — what could not be determined. Often the most actionable section.
- **Recommended next steps.**
- **The audit trail** — every step: tool called, stated reason, status, evidence IDs
  revealed, duration. Rejected actions appear too, with the schema error.

Surfacing rejections rather than hiding them is deliberate. An analyst reading *"step 3:
rejected — duplicate tool call"* understands the agent's behaviour and calibrates trust
accordingly. A UI that only shows successes teaches the reader that the agent is more
reliable than it is.

---

## 8. Extending the dashboard

Adding a panel for a new analyzer stage:

1. Add a container `<section>` in `index.html`, `class="glass rounded-2xl p-5 hidden"`.
2. In `render()`, read the new field, `esc()` every interpolated value, unhide the
   section when data exists.
3. Add the corresponding section to `report.py` so the PDF matches the dashboard.
4. If it has an availability flag, surface it in `refreshHealth()`.

Keep the panel hidden when the stage did not run. See
[15 — Extending](15-extending.md).

---

**Next:** [12 — Deployment & Ops](12-deployment-and-ops.md).
