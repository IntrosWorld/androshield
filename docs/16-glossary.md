# 16 — Glossary

Every term used across this documentation, defined.

---

## Android platform

**ADB (Android Debug Bridge)** — Command-line tool for communicating with an Android
device or emulator. Used by the [dynamic sandbox](09-dynamic-analysis.md) to install,
launch, observe, and uninstall.

**Accessibility Service** — An API designed for screen readers that grants an app the
ability to read the content of every other app's screen and to synthesise taps and text
input. The most abused capability in Android banking fraud. Weight 20 — the highest
single permission weight in the system.

**activity-alias** — A manifest entry exposing an activity under an alternative name;
also checked by the exported-component stage.

**ART (Android Runtime)** — The runtime that executes Android apps, compiling DEX
bytecode ahead-of-time and just-in-time into native code.

**AVD (Android Virtual Device)** — An emulator configuration. The dynamic sandbox targets
one named by `SANDBOX_AVD` (default `FraudSandbox`) and deliberately never falls back to
an arbitrary attached device.

**AXML** — Android's binary XML encoding. `AndroidManifest.xml` inside an APK is AXML,
not text; androguard decodes it. See [01 §3.1](01-foundations.md#31-it-is-not-text-xml).

**APK (Android Package)** — A ZIP archive containing an app's bytecode, manifest,
resources, native libraries, and signature.

**BroadcastReceiver** — A component that responds to system or app events. Fraud APKs use
`SMS_RECEIVED` and `BOOT_COMPLETED` receivers to activate without a launcher icon.

**DEX (Dalvik Executable)** — Compiled Android bytecode. Register-based, with shared
deduplicated pools for strings, types, and methods. See
[01 §5](01-foundations.md#5-dex--the-compiled-code).

**Device Admin** — An elevated privilege allowing lock/wipe and resisting uninstallation.

**Exported component** — A component reachable by other apps. Explicit via
`android:exported="true"`, or implicit via an `intent-filter` on pre-Android-12 targets.
Treated here as a **vulnerability**, not as evidence of maliciousness.

**Intent filter** — A manifest declaration of which intents a component handles. Its
presence implies export on older target SDKs.

**Multidex** — Splitting an app across `classes.dex`, `classes2.dex`, … past the 64K
method limit. Routine engineering; scored **0**.

**Notification Listener Service** — Receives the content of every notification on the
device. Used for quiet OTP theft; also legitimately used by smartwatch companions and
launchers, hence weight 5.

**Overlay** (`SYSTEM_ALERT_WINDOW`) — Draw over other apps. The mechanism behind fake
login screens, but also chat heads and screen filters — hence weight 4, with danger
recovered through correlation.

**Repackaging** — Decompiling a legitimate app, injecting malicious code, rebuilding, and
re-signing with the attacker's key. The dominant fraud distribution method.

**Special access permission** — A permission requiring the user to visit a Settings
screen rather than answer a prompt (`SYSTEM_ALERT_WINDOW`,
`BIND_ACCESSIBILITY_SERVICE`, `REQUEST_INSTALL_PACKAGES`, notification access). Malware
social-engineers users into these.

**Type descriptor** — DEX's type encoding: `Landroid/telephony/SmsManager;`, `[B`, `I`.

**`v1`/`v2`/`v3`/`v4` signing** — Successive APK signature schemes. All prove integrity;
none prove trustworthiness, because Android apps are self-signed.

---

## Analysis concepts

**Analysis quality** — `full` (manifest + DEX strings + call graph), `partial` (manifest
+ raw strings, no call graph), or `failed` (nothing usable ⇒ score `null`, severity
`Unknown`). See the [degradation ladder](04-static-analysis-pipeline.md#3-the-degradation-ladder).

**Call graph / cross-reference (xref)** — The recovered map of which method calls which.
`get_xref_from()` answers "who calls this?", enabling the invoked-vs-referenced
distinction.

**Category cap** — A per-category maximum contribution to the score, preventing any one
feature class from dominating.

**Correlation rule** — A bonus awarded when a *combination* of capabilities forms a
discriminative fraud chain. The core of the scoring model.

**Degradation ladder** — The three-rung fallback from full parse to manifest-only to
failure, ensuring a parse failure never presents as a clean result.

**Diminishing returns** — Permission scoring at 100 % / 50 % / 25 % of successive weights,
preventing breadth from being mistaken for intent.

**Entropy (Shannon)** — `-Σ p·log₂p` over a string's character distribution. >4.5
bits/char suggests encryption or encoding. Triggered on a **ratio** of candidates, never
an absolute count, so the signal is scale-invariant.

**Evidence type** — `invoked` (a callsite was recovered; high confidence, full weight) vs
`reference` (descriptor present in the string pool only; low confidence, reduced weight).

**IOC (Indicator of Compromise)** — An observable artefact: hash, URL, domain, IP, bot
token, hardcoded secret.

**Library context** — When *every* recovered caller of a detected API lives in a known
SDK namespace. The finding is kept for the report but scored **0** — framework module
loading is not a dropper.

**Obfuscation** — Deliberately hindering analysis: name minification, string encryption,
packing, dynamic loading.

**Packer** — A tool that encrypts the real DEX and unpacks it at runtime. Detected by
APKiD by fingerprint, not by content.

**Severity band** — Low (0–20), Medium (21–40), High (41–70), Critical (71–100),
`Unknown` (analysis failed).

**Score breakdown** — The itemised `{category, points, detail}` list whose points sum
exactly to `risk_score` before the 100 clamp. The explainability contract.

**String pool** — The deduplicated table of every literal string in a DEX. The primary
IOC source.

---

## Threats

**C2 (Command and Control)** — The attacker's channel for instructions and exfiltration.
Common here: Telegram Bot API, Firebase, plain HTTP.

**Dropper** — A near-empty first-stage app that downloads and loads its real payload at
runtime. Detected by the loader pattern, not the payload.

**Exfiltration** — Moving stolen data off the device.

**Keylogging** — Capturing input; on Android usually via accessibility rather than a
keyboard hook.

**On-device fraud** — Initiating a transaction inside the victim's own authenticated
session using accessibility control. Defeats device-binding and 2FA, because the
transaction is genuinely from the victim's device.

**OTP (One-Time Password)** — The SMS or push code used for 2FA. The primary target.

**Overlay attack** — Drawing a fake login screen over a real banking app.

**Smishing** — Phishing over SMS; the usual delivery vector for fraud APKs.

**Sideloading** — Installing an APK from outside an app store.

---

## Tools and data

**androguard** — Pure-Python Android analysis library. Parses AXML, DEX, certificates, and
builds the call graph. Chosen for its **zero-JDK dependency chain**.

**AndroZoo** — A large APK repository, recommended as the independent, hash-pinned benign
source once institutional access is approved. No key is configured in this workspace.

**APKiD** — Fingerprints the compiler, packer, protector, and anti-analysis techniques
used to build an APK — "the PEiD of Android".

**CICMalDroid-2020** — 17 341 APKs across Adware, Banking, SMS Malware, Riskware, Benign;
11 598 usable labelled records. The primary evaluation dataset here.

**Drebin** — 5 560 malware APKs, 179 families, 2010–2012, with pre-extracted features.
Useful for cross-dataset recall; far too old to be a sole training source.

**Frida** — Dynamic instrumentation toolkit that injects a JS engine into a running
process for live method hooking. **Pinned to 16.x** — Frida 17 removed the global `Java`
bridge the hook script needs.

**Ollama** — Local LLM server; the default agent provider, so evidence stays on the
analyst's machine.

**MITRE ATT&CK Mobile** — The standard taxonomy of adversary techniques. Mapped here for
presentation; **never scored**.

**VirusTotal** — Multi-engine scanning service. The **only** source that can produce a
`Confirmed Malicious` verdict in this system.

**YARA** — Pattern-matching engine for classifying files by rules. Used offline over a
synthetic text blob of DEX strings, native strings, namespaced permissions, and the
package name.

**yara-python-dex** — The YARA binding pulled in by `apkid`. It changes the string-match
API, which `_matched_identifiers()` handles for both shapes.

---

## System components

**Agent (bounded)** — An LLM that plans evidence-gathering using allowlisted read-only
tools under step, tool-call, time, and invalid-action budgets. Structurally cannot alter
the score.

**Approval tool** — An agent tool that records a proposal (`request_dynamic_analysis`,
`request_external_intel`) and returns `executed: false`. It never performs the action.

**Evidence graph** — The immutable, bounded, ID-addressed representation of findings the
agent reasons over. Built from a `deepcopy`.

**Evidence ID** — A stable `kind:slug` identifier. Hypotheses must cite IDs the model
genuinely retrieved, or validation rejects them.

**Multi-engine consensus floor (removed)** — A legacy scoring rule that allowed independent AV
agreement (≥3 engines ⇒ 41, ≥5 ⇒ 71), applied as an explicit breakdown entry so the sum
invariant holds.

**Operating threshold** — The ML alert threshold, chosen on the **validation** split as
the lowest value meeting ≥98 % benign specificity.

**Policy version** — `agent-policy-v1`; stamped on every investigation for auditability.

**Progressive disclosure** — The agent first sees only evidence IDs and summaries; details
require a tool call. Keeps context small and makes citation verifiable.

**Score invariant** — The rule that no AI component may change `risk_score`, `severity`,
or `score_breakdown`. Enforced four independent ways.

**Template fallback** — The deterministic report generated from findings alone when no
model is configured or the model fails. Guarantees the platform is fully functional with
zero API keys.

**Threat assessment** — The report verdict: `No Strong Malicious Evidence`, `Suspicious`,
`Likely Malicious`, or `Confirmed Malicious`. The last is reachable **only** via
multi-engine corroboration.

---

## Metrics

**Accuracy** — (TP+TN)/N. Misleading under class imbalance; reported, never headlined.

**Campaign leakage** — Near-identical repackaged variants appearing in both train and
test, inflating every metric. Prevented by family-aware de-duplication and temporal
splits (Phase 2).

**Flag rate** — Proportion of a class scoring at or above the decision threshold (21).
Reported per class **instead of** family accuracy, because the platform produces a
malware-risk score, not a family label.

**Precision** — TP/(TP+FP). Of flagged samples, how many are genuinely malicious.

**Recall (sensitivity)** — TP/(TP+FN). Of malicious samples, how many were caught.

**ROC-AUC** — Threshold-independent ranking quality.

**Specificity** — TN/(TN+FP). Of benign samples, how many were correctly left alone.
**The metric this project optimises**, because a tool that cries wolf gets ignored — and
an ignored tool has zero effective recall.

**Training/serving skew** — When features computed at training time differ from those
computed at inference. The reason the ML model uses permissions only. It fails
*silently*, which is what makes it dangerous.

---

**Back to:** [Documentation index](README.md)
