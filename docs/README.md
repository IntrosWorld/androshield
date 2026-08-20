# APKGuard — The Complete Guide

> A generative-AI platform for automated **static analysis and explainable risk scoring
> of fraudulent Android APKs**, built for banking-fraud and SOC first-level triage.

This directory is the project's full documentation set. It is written to be read
**front to back with no prior Android or malware-analysis knowledge**, and it does not
stop at the beginner level — every subsystem is documented down to the exact rule
weights, data structures, invariants, and failure modes that are in the code.

---

## How to read this

| If you are… | Start at | Then read |
|---|---|---|
| Completely new to Android internals | [01 — Foundations](01-foundations.md) | 02 → 03 → 04 |
| A security analyst evaluating the tool | [02 — Threat Model](02-threat-model.md) | 05, 13, 14 |
| An engineer joining the codebase | [03 — Architecture](03-architecture.md) | 04, 05, 10, 15 |
| Interested in the AI/agentic parts | [06 — GenAI Reporting](06-genai-reporting.md) | 07, 08 |
| Deploying or operating it | [12 — Deployment & Ops](12-deployment-and-ops.md) | 10, 14 |

---

## Table of contents

### Part I — Theory from scratch
| # | Document | What it covers |
|---|---|---|
| 01 | [Foundations](01-foundations.md) | What an APK actually *is*: ZIP, AXML, DEX, ART, manifest, permission model, code signing, the Android security model. No prior knowledge assumed. |
| 02 | [Threat Model](02-threat-model.md) | The mobile banking-fraud landscape: OTP theft, overlay trojans, accessibility abuse, droppers, notification theft, device-admin persistence, Telegram C2. Mapped to MITRE ATT&CK Mobile. |

### Part II — The system
| # | Document | What it covers |
|---|---|---|
| 03 | [Architecture](03-architecture.md) | End-to-end architecture, module map, request lifecycle, trust boundaries, data model, design principles. |
| 04 | [Static Analysis Pipeline](04-static-analysis-pipeline.md) | Every analyzer stage in depth: parsing, manifest, certificate, components, permissions, API detection, IOC extraction, obfuscation, YARA, APKiD, MITRE. Including the degradation ladder. |
| 05 | [Risk Scoring](05-risk-scoring.md) | The scoring theory: category caps, diminishing returns, correlation chains, evidence confidence, fusion with VirusTotal and ML, severity bands. Worked examples. |

### Part III — The intelligence layers
| # | Document | What it covers |
|---|---|---|
| 06 | [GenAI Reporting](06-genai-reporting.md) | Gemini report generation, prompt engineering, the evidence-assessment policy, output validation, deterministic template fallback. |
| 07 | [Agentic Investigation](07-agentic-investigation.md) | The bounded agent: evidence graph, allowlisted tools, strict schemas, budgets, providers, prompt-injection defence, and the non-negotiable score invariant. |
| 08 | [ML Classifier](08-ml-classifier.md) | Permission-space feature engineering, Drebin/CICMalDroid training, operating thresholds, hybrid rule+ML fusion, and why numeric features were deliberately excluded. |
| 09 | [Dynamic Analysis](09-dynamic-analysis.md) | The opt-in emulator sandbox: adb tier, Frida tier, runtime scoring, and the safety rules that make execution acceptable. |

### Part IV — Interfaces and operations
| # | Document | What it covers |
|---|---|---|
| 10 | [API Reference](10-api-reference.md) | Every endpoint, request/response schema, status codes, and the full analysis JSON contract. |
| 11 | [Frontend](11-frontend.md) | The single-page dashboard: rendering model, panels, XSS handling, health badges. |
| 12 | [Deployment & Ops](12-deployment-and-ops.md) | Local setup, environment variables, Docker, troubleshooting, performance. |

### Part V — Rigour
| # | Document | What it covers |
|---|---|---|
| 13 | [Evaluation & Accuracy](13-evaluation-and-accuracy.md) | The evaluation harness, CICMalDroid-2020 protocol, metric definitions, the pinned benign corpus, and an honest statement of what the numbers do and do not prove. |
| 14 | [Security Model](14-security-model.md) | Trust boundaries, the never-execute rule, upload hardening, prompt-injection defence, data handling. |
| 15 | [Extending the Platform](15-extending.md) | How to add a permission, an API signature, a YARA rule, a correlation chain, an agent tool, or a new analyzer stage — with the tests each requires. |
| 16 | [Glossary](16-glossary.md) | Every term used in this documentation, defined. |

---

## The three rules that shape everything

Every design decision in this codebase traces back to one of three constraints.

1. **The static pipeline never executes the APK.** Parsing is not execution. Execution
   happens only in the opt-in emulator sandbox, only inside the user's own AVD, and
   only when a human explicitly triggers it.
2. **The score is rule-based and explainable.** Every point of the 0–100 risk score is
   attributable to a named category with a human-readable reason. A model may *inform*
   the score; it may never *be* the score.
3. **Only extracted findings reach the LLM.** The model receives a bounded, structured
   evidence object — never raw APK bytes, never file paths, never the sample itself.

A fourth rule governs the code style: **analyzers are defensive**. A failure in one
stage degrades to a partial result. It never crashes the request.

---

## One-paragraph summary of the system

A user uploads an `.apk`. The server streams it to a bounded temporary file, hashes it,
and parses it with **androguard** (pure Python — no Java toolchain). Ten independent
analyzer stages extract manifest metadata, certificate red-flags, exported attack
surface, dangerous permissions, invoked suspicious APIs, network IOCs, obfuscation
signals, YARA signature matches, APKiD packer fingerprints, and MITRE ATT&CK technique
mappings. A transparent rule engine fuses those into a 0–100 score with an itemised
breakdown, applying category caps, diminishing returns, and correlation bonuses for
discriminative fraud chains. Optional layers fold in **VirusTotal** multi-engine
corroboration and a **permission-space ML classifier**. An optional **bounded agent**
then reasons over an immutable evidence graph using only allowlisted read-only tools,
producing evidence-cited hypotheses — and is structurally forbidden from changing the
score. Finally **Gemini** writes an analyst-grade report (with a deterministic template
fallback), everything is persisted to SQLite, and the dashboard renders it with PDF and
IOC exports.
