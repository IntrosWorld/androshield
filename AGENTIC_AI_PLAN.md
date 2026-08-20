# Agentic AI plan for APK fraud analysis

> Implementation status: the bounded orchestrator, Ollama/Gemini providers, evidence
> graph, policy enforcement, audit trail, API/dashboard integration, persistence,
> optional Gemini review, PDF output, automated tests, and live Ollama smoke test are
> implemented on branch `exp-2-agentic`.

## Decision

Add a bounded investigation agent, not an unrestricted autonomous agent. The agent may
choose and sequence approved, read-only analysis tools, but it may not execute an APK,
run arbitrary shell commands, write outside its case workspace, change the explainable
risk score, or contact an unapproved external service.

The default worker model is local `qwen3:8b` through Ollama. Gemini remains optional as
the higher-quality reviewer and report writer. Both receive extracted evidence only;
neither receives the raw APK.

## Why this model split

| Role | Default provider | Purpose |
|---|---|---|
| Investigator | Ollama / `qwen3:8b` | Private, offline planning; select the next static-analysis tool; correlate evidence |
| Code specialist | Ollama / existing `qwen2.5-coder:7b` | Explain recovered Java/Dalvik snippets and propose names for obfuscated symbols |
| Reviewer | Gemini, opt-in | Challenge unsupported conclusions, summarize the evidence and recommend SOC actions |
| Verdict and score | Existing deterministic pipeline | Produce the auditable score, severity and reason breakdown |

`qwen3-coder:30b` is not the default because its 19 GB download and runtime memory
requirements are a poor fit for the current 16 GB laptop. A specialized community
"cyber" fine-tune is also not the default: provenance and tool-call reliability matter
more than a cyber label. We will evaluate alternatives before changing the model.

## Investigation loop

1. The deterministic analyzer creates an immutable evidence bundle and evidence IDs.
2. The local planner receives the case goal, compact evidence, tool schemas and budget.
3. It returns one structured action or a final hypothesis.
4. The orchestrator validates the action against the allowlist and policy.
5. The tool runs and its result is appended to the audit trail.
6. The loop ends on a final answer or on step, time, token, duplicate-action or error
   limits.
7. The deterministic scorer calculates the verdict. Gemini may review the narrative but
   cannot override the score or invent confirmation.

Every action response must match one of these shapes:

```json
{"type":"tool","tool":"search_strings","arguments":{"query":"sms"},"reason":"Check the credential-theft hypothesis","evidence_ids":["permission:READ_SMS"]}
```

```json
{"type":"final","hypotheses":[{"claim":"...","confidence":"medium","evidence_ids":["..."]}],"gaps":["..."]}
```

## Tool and action policy

### Automatic, read-only static tools

- Read manifest, permissions, components and certificate metadata.
- Search already extracted strings and decoded blobs.
- Query the recovered DEX call graph, callers, callees and bounded method slices.
- Correlate IOCs, YARA/APKiD matches and MITRE techniques.
- Re-run an existing analyzer with stricter limits against the same extracted case.
- Generate a proposed investigation note with evidence citations.

### Explicit opt-in or confirmation

- Send a compact evidence bundle to Gemini.
- Query VirusTotal or another network intelligence service.
- Start dynamic analysis in the dedicated, disposable Android emulator.
- Export or share a report outside the application.

### Prohibited

- Execute or install the APK on the host.
- Give the model a shell, unrestricted filesystem, browser or arbitrary HTTP tool.
- Let text embedded in an APK redefine the system prompt or tool policy.
- Upload a raw APK, credentials, complete decompiled source or unrelated user data to an
  LLM provider.
- Let an LLM directly assign, increase or decrease the risk score.
- Automatically remediate, delete, block or publish an IOC without human approval.

Dynamic analysis remains a separate, explicit workflow and may run only in the isolated
AVD. The static `/api/analyze` route never executes the sample.

## Security and robustness controls

- Treat APK names, strings, source comments and resources as untrusted quoted data, not
  instructions; wrap them in typed JSON fields.
- Validate tool calls and final outputs with strict schemas; reject unknown fields and
  tools.
- Bind the active case identity inside the orchestrator. The model selects an operation
  but never copies or supplies the APK hash, database ID, storage path or tenant ID.
- Use `max_steps=8`, per-tool timeouts, bounded result sizes and duplicate-call detection.
- Assign stable evidence IDs and require each material claim to cite at least one ID.
- Label inference separately from observed facts and show missing evidence.
- Redact secrets and personal data before any cloud call.
- Record provider, model digest, prompt-policy version, actions, timings, errors and
  evidence IDs in an append-only case trace.
- Fall back to the current deterministic report when Ollama or Gemini is unavailable.
- Cache only by APK SHA-256 plus analyzer/model/policy versions.

## Proposed code layout

```text
backend/app/agent/
  orchestrator.py       bounded state machine and budgets
  policy.py             tool/action authorization and approval tiers
  schemas.py            strict request, tool-call and hypothesis schemas
  evidence.py           compact evidence graph and stable IDs
  audit.py              append-only action trace
  tools/
    static.py           allowlisted adapters over existing analyzers
    dex.py              bounded call-graph and method-slice queries
    intel.py            approval-gated external intelligence
    dynamic.py          approval-gated isolated-AVD request only
backend/app/genai/
  provider.py           provider interface
  ollama_client.py      local chat/tool calls
  gemini_client.py      existing report path plus optional reviewer
```

The provider interface should expose `plan_next(evidence, tools, budget)` and
`review(draft, evidence)`. Tool execution belongs to the orchestrator, never to the
provider client.

## Configuration proposal

```dotenv
AGENT_ENABLED=false
AGENT_MAX_STEPS=8
AGENT_TOOL_TIMEOUT_SECONDS=30
AGENT_EXTERNAL_ACTIONS=false
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen3:8b
OLLAMA_CODE_MODEL=qwen2.5-coder:7b
AGENT_GEMINI_REVIEW=false
```

Keep all agentic behavior disabled by default until the evaluation gates below pass.

## Delivery phases

### Phase A - local provider and one safe tool

- Add provider/schema modules and Ollama health check.
- Implement one read-only `get_case_summary` tool.
- Verify valid tool calls, invalid-call rejection, timeouts and deterministic fallback.

### Phase B - evidence-guided static investigation

- Add evidence IDs and the allowlisted static/DEX tools.
- Add the bounded loop, audit trace and a UI action timeline.
- Test prompt injection strings embedded in APK resources.

### Phase C - Gemini reviewer and approvals

- Retain the existing Gemini report function.
- Add an opt-in reviewer using the same redacted evidence bundle.
- Add visible confirmations for all network and dynamic actions.

### Phase D - evaluation and controlled release

- Replay the MalDroid banking and benign sets without executing them.
- Measure tool-call validity, grounded-claim precision, unsupported-claim rate, latency,
  failure recovery and analyst time saved.
- Compare local-only, Gemini-only and local-plus-Gemini modes on the same frozen cases.
- Enable the feature only after zero policy escapes, zero raw-APK cloud uploads, at
  least 95% schema-valid tool calls and no regression in deterministic scoring tests.

## Definition of done

- The local agent works with the network disconnected after model download.
- Every claim in the UI links to observed evidence or is visibly marked as a hypothesis.
- Every attempted action is visible in the case audit trail.
- Unknown tools, shell requests and prompt-injection attempts are rejected and tested.
- Gemini can be disabled without breaking analysis or reporting.
- Dynamic execution still requires a separate user confirmation and isolated AVD.
- Risk score and severity remain reproducible without either LLM.
