# 13 — Evaluation and Accuracy

> The chapter that refuses to overclaim. Every number here is labelled with what it does
> and does not prove.

Sources: [MALDROID_EVALUATION.md](../MALDROID_EVALUATION.md),
[ROBUSTNESS_PLAN.md](../ROBUSTNESS_PLAN.md), [TEST_CORPUS.md](../TEST_CORPUS.md),
[`backend/tools/evaluate_maldroid.py`](../backend/tools/evaluate_maldroid.py)

---

## 1. The claim this project makes

> **A risk score is an explainable triage ranking. It is not a calibrated malware
> probability, and it will not be described as one until the evaluation and calibration
> gates in the robustness plan are met.**

That sentence is the honest position, and it is repeated in the code, the plans, and the
report policy. Concretely:

- No accuracy figure is presented as a production metric.
- The word *"Confirmed"* is reserved for independent multi-engine agreement.
- "Production ready" is explicitly not claimed before the Phase-4 gate.

---

## 2. Why measuring this is genuinely hard

| Obstacle | Consequence |
|---|---|
| **No ground truth for "malicious"** | Labels come from AV consensus or dataset curation, both imperfect |
| **Campaign leakage** | Random splits put near-identical repackaged variants in train *and* test, inflating every metric |
| **Concept drift** | A 2014 corpus does not represent current fraud; metrics on it do not transfer |
| **Benign is the hard class** | Malware corpora are plentiful; a *modern, adversarial* benign corpus is not |
| **Dataset ≠ production traffic** | Real submissions to a fraud desk have a different mix entirely |
| **Curation artefacts** | A corpus assembled by one method may be separable by that method rather than by maliciousness |

Any project reporting "99.2 % accuracy" on a public Android malware dataset without
addressing de-duplication and temporal splitting is, in all likelihood, reporting
leakage.

---

## 3. The evaluation harness

```powershell
.\.venv\Scripts\python.exe tools\evaluate_maldroid.py `
  --dataset "F:\datasets\CICMalDroid-2020" `
  --limit-per-class 25 `
  --seed 2020
```

Writes `summary.json` and per-sample `samples.csv` under
`backend/data/evaluations/maldroid/` (git-ignored).

| Property | Value |
|---|---|
| Analysis mode | **Static only** — never installs or executes an APK |
| Decision threshold | **21** (Medium or above = flagged) |
| Positive classes | Adware, Banking, SMS Malware, Riskware |
| Negative class | Benign |
| Metrics | Confusion matrix, accuracy, precision, recall, specificity, F1, parse failures, per-class flag rate |
| Determinism | `--seed` fixes sampling |

Two design decisions in the harness:

- **Per-class flag rate instead of family classification.** The platform produces a
  malware-*risk* score, not a five-way family label. Reporting per-class flag rate is
  honest; reporting family accuracy would be pretending to do a task it does not do.
- **Parse failures are reported separately as coverage gaps, never as benign
  predictions.** Counting an unparseable sample as a negative would silently inflate
  specificity — precisely the failure the `Unknown` severity exists to prevent.

### Bounded archive sampling

CICMalDroid's class archives are enormous (`Benign.tar.gz` is 47.5 GiB). Rather than
extracting everything:

```powershell
.\.venv\Scripts\python.exe tools\sample_maldroid_archive.py `
  "F:\datasets\Benign.tar.gz" "F:\datasets\benign-sample" `
  --class-name Benign --count 20 --max-total-mb 500
```

The sampler accepts **only** regular `Class/<sha256>.apk` members (no links, no path
traversal), **verifies each APK against its hash filename**, enforces per-file and total
byte limits, and stops reading the archive once the requested count is reached.

> A first-N or `--skip`-offset batch is convenient development data — **not a random or
> independently representative test set.** The tool's own documentation says so.

---

## 4. Results obtained so far, with their caveats

### 4.1 Local regression set (4 samples)

| Sample | Role | Before calibration | After |
|---|---|---:|---:|
| Synthetic fraud fixture | Strong suspicious fixture | 100 / Critical | 100 / Critical |
| Packed dropper `.w.apk` | Malicious/dropper regression | Critical | 76 / Critical |
| OpenCalculator | Known benign | 38 / Medium | **17 / Low** |
| Outfit7 legacy ad-heavy app | Known benign stress case | 66 / High | **20 / Low** |

> **These four samples are smoke tests, not publishable accuracy evidence.**

### 4.2 CICMalDroid Banking archive (25 samples, 2026-08-15)

Archive: 2 505 APK members, 4.17 GB uncompressed, SHA-256 `353c9d80…8ffa7`, no path
traversal or link entries. Windows Defender quarantined some extracted samples; security
controls were **not** disabled or bypassed.

| Coverage / result | Count |
|---|---:|
| Full DEX analysis | 22 |
| Partial fallback | 3 |
| Failed | 0 |
| Flagged (≥21) | 21 |
| Below threshold | 4 |

Banking-only flag rate: **84 %**.

> **This is not an accuracy measurement.** Without a paired benign archive, false-positive
> rate, specificity, and balanced accuracy cannot be computed. A detector that flags
> everything scores 100 % here.

The degradation ladder paid off measurably: of six malformed samples from an earlier
baseline, the fallback recovered **all six** as `partial` results and flagged five
(scores 83–98); the remaining score-9 sample is correctly reported as `Inconclusive`
rather than clean.

### 4.3 Benign slice and the calibration that followed (2026-08-17)

A bounded first-20 slice of `Benign.tar.gz` (20 hash-named APKs, 275.87 MiB). All 20
completed full static analysis; none was installed or executed.

| Stage | Flagged / 20 | Specificity | Mean benign score |
|---|---:|---:|---:|
| Before benign-driven calibration | 19 | **5 %** | 46.5 |
| After contextual/diminishing scoring | 8 | **60 %** | 24.55 |

Root causes found by inspection — and every one of them is now a documented suppression
rule in [04](04-static-analysis-pipeline.md) and [05](05-risk-scoring.md):

1. Double/triple counting from broad permission sets → **diminishing returns**
2. Library-only `DexClassLoader` calls → **library-context suppression**
3. Uncorroborated notification-listener use → **correlation requirement**
4. Generic Internet capability scored as a finding → **removed from the weight table**

Re-running the Banking-25 regression after calibration: **22/25 flagged (88 %)**, mean
score 71.56, 22 full + 3 partial, zero failures. Two samples that dropped below threshold
had previously crossed it *almost entirely through Google-library dynamic-loader
signals* — retaining those points would have knowingly restored a false-positive
mechanism.

**That trade is the whole story of the calibration work: recall 84 % → 88 % while benign
specificity went 5 % → 60 %.** Both moved in the right direction because the removed
points were noise, not signal.

Combined 45-sample results:
`backend/data/evaluations/maldroid_banking25_benign20_recalibrated/`.

> Still calibration evidence only. The first 20 archive entries are neither random nor
> held out.

### 4.4 ML baseline on the official CSV matrix

Consumed CICMalDroid's `CSV.zip` directly (without extracting its 595 MB static matrix):
**11 598 aligned samples.**

| Class | Category | Rows |
|---:|---|---:|
| 1 | Adware | 1 253 |
| 2 | Banking | 2 100 |
| 3 | SMS Malware | 3 904 |
| 4 | Riskware | 2 546 |
| 5 | Benign | 1 795 |

206 permission features were selected from the 50 621-column static matrix. The 139
syscall and 470 syscall/Binder runtime features were **deliberately excluded** — static
analysis cannot reproduce them at inference time ([08 §2](08-ml-classifier.md#2-the-feature-space-and-one-non-obvious-constraint)).

Stratified 64 / 16 / 20 split. The validation partition selected a conservative
**0.7277** alert threshold targeting ≥98 % benign specificity. On the untouched
row-level test partition:

| Metric | Value |
|---|---:|
| ROC-AUC | **0.989** |
| Benign recall / specificity | **97 %** |
| Malware recall | **93 %** |

Independent benign controls stayed **Low with zero ML score contribution**.

> **These figures remain development evidence.** The released matrix lacks the hashes
> required for campaign de-duplication and a temporal split. Row-level splitting cannot
> exclude near-duplicate variants of the same campaign appearing on both sides.

Integration effect: on the same Banking-25 batch, conservative ML corroboration raised
flags from 21 to 24 — an **integration regression result, not independent validation**,
because CICMalDroid CSV rows supplied the training corpus and cannot be hash-matched
against the APK batch to exclude overlap.

---

## 5. The pinned benign corpus

Malware corpora are easy; **adversarial benign apps are the scarce resource.** The corpus
is chosen so that every entry looks malicious to a naive detector.

| App | Stress vector | SHA-256 (prefix) |
|---|---|---|
| Fossify Calculator 1.4.0 | Reproducible clean baseline (F-Droid-verified reproducible build) | `7c5443c2…` |
| OWASP UnCrackable L1 | Root detection, anti-debug, obfuscation — benign but *looks packed* | `1da8bf57…` |
| Aegis 3.4.2 | OTP vocabulary, cryptography, boot receiver, clipboard | `ab633d31…` |
| KeePassDX 4.4.5 | Credential vocabulary, clipboard, package visibility | `23d6917b…` |
| Material Files 1.7.4 | Storage management, install-packages, shell + network code | `ebc5138b…` |
| NewPipe 0.29.0 | Overlay, boot, sockets, crash collection, credential-like strings | `1765284f…` |

Rules of the corpus:

- Binaries live under `samples/external-test-corpus/`, **git-ignored**.
- Every download is hash-verified before analysis.
- **A differing hash is never silently accepted** — review the upstream version and record
  the new expected hash as a deliberate corpus change.
- Test inputs only; the static pipeline must never execute them.

---

## 6. Metric definitions

For a threshold of 21 (Medium or above = flagged):

| Metric | Formula | Meaning here |
|---|---|---|
| Accuracy | (TP+TN)/N | Misleading under class imbalance — reported, never headlined |
| Precision | TP/(TP+FP) | Of samples we flag, how many are actually malicious |
| Recall (sensitivity) | TP/(TP+FN) | Of malicious samples, how many we catch |
| **Specificity** | TN/(TN+FP) | Of benign samples, how many we correctly leave alone |
| F1 | harmonic mean(P, R) | Single summary; hides the asymmetric cost |
| ROC-AUC | — | Threshold-independent ranking quality |
| Parse failure rate | failed/N | **Coverage gap — never counted as a prediction** |

**Specificity is the metric this project optimises**, for the reason in
[08 §5](08-ml-classifier.md#5-threshold-selection-specificity-first): a triage tool that
cries wolf gets ignored, and an ignored tool has zero effective recall.

---

## 7. The roadmap to defensible numbers

From [ROBUSTNESS_PLAN.md](../ROBUSTNESS_PLAN.md).

### Phase 1 — Evidence correctness and safety ✅ implemented

Exact method matching with recovered callsites; stop scoring ubiquitous permissions,
ordinary HTTPS links, native libraries, generic commerce words, and exported attack
surface; DNS-boundary-safe allowlisting; correlation rules; APKiD anti-VM capping;
`Confirmed Malicious` reserved for multi-engine agreement; upload streaming and bounds,
CORS defaults, device-selection validation, output escaping; fast regression coverage.

### Phase 2 — Reproducible evaluation harness

1. Hash-only dataset manifest: source, collection date, family, label provenance,
   train/validation/test partition. **Never commit raw APKs.**
2. **Family-aware de-duplication and temporal splits** to prevent campaign leakage.
3. Batch-run into versioned JSON feature records.
4. Report precision, recall, F1, FPR, ROC/PR-AUC, confusion matrices, per-family recall,
   processing-time percentiles.
5. Tune thresholds on validation only; **lock the test partition until release**.
6. Maintain a modern benign suite: finance, accessibility, overlay, antivirus, VPN,
   ad-heavy, games, enterprise management.

> **Release gate:** no detector-weight change without before/after metrics and named
> regression cases. Operating points are agreed with the bank/SOC team, not invented from
> demo samples.

### Phase 3 — Calibrated ML corroboration

Versioned real-data training; identical train/serve features; compare logistic
regression, Random Forest, gradient boosting on the same partitions and class costs;
Platt or isotonic calibration on validation only; model-card metadata (dataset versions,
time range, metrics, limitations, feature-vocabulary hash, training-code revision);
**refuse to load bundles lacking schema/version metadata**.

> **Release gate:** the ML output is called a *probability* only after calibration error
> and temporal/cross-dataset performance are reported. Until then it is a labelled
> corroborating signal.

### Phase 4 — Dynamic/static fusion and operational hardening

Persist dynamic runs separately, fused only through explicit evidence entries; interaction
scripts, network capture outside logcat, filesystem-delta collection, payload-hash
provenance; authenticated localhost/isolated-lab-only dynamic execution with a single-run
device lock, cancellation, worker timeout, automatic snapshot restore; resource-limited
static workers, rate limits, structured audit logs, retention controls, DB migrations;
vendored frontend assets for offline labs; CI for tests, synthetic-APK smoke analysis,
dependency checks, and container builds.

> **Release gate:** threat-model review, recovery test, isolated-network validation, and a
> documented operator runbook. **The phrase "production ready" should not be used before
> this gate is satisfied.**

---

## 8. Independent data sources

### AndroZoo — the recommended independent benign source

[AndroZoo](https://androzoo.uni.lu/) provides a modern, hash-pinned benign partition.
Protocol: one APK per package from `play.google.com`, require `vt_detection=0`, record
`vt_scan_date`, prefer recent scans, manually review outliers, keep the final hash
manifest immutable, and never train on the package families used for the final test.

> A zero VirusTotal count is a **selection rule, not proof of benignness.**

Access requires a personal API key from an institutional email; key sharing,
redistribution, and commercial use are prohibited. **No key is configured in this
workspace, and no AndroZoo APKs have been downloaded.**

### Drebin — cross-dataset recall test

[Drebin](https://drebin.mlsec.org/): 5 560 malware APKs, 179 families, 2010–2012. Useful
for recall on older families and for the permission-feature trainer, but it is not a
benign corpus and is far too old to be a sole training source. Keep it as a **separate
cross-dataset evaluation**, never mixed into a CICMalDroid held-out result.

### CICMalDroid-2020

Obtain via CIC's official *Download the dataset* link and its registration form. Direct
file browsing is access-controlled. **Never commit archives or APKs** — `*.apk` and
`samples/` are git-ignored. Cite the dataset papers listed on CIC's page in any
publication.

---

## 9. Summary of what is and is not established

| Claim | Status |
|---|---|
| The pipeline runs static-only and never executes an APK | ✅ Established by design and code |
| Malformed samples degrade to `partial`/`Unknown`, never to clean | ✅ Verified on six malformed samples |
| Calibration cut benign false positives 19/20 → 8/20 while holding malware recall at 88 % | ✅ Measured, on a **non-random** slice |
| Permission RF reaches ROC-AUC 0.989 on a row-level CICMalDroid split | ⚠️ Development evidence — no campaign de-duplication, no temporal split |
| The system generalises to production fraud traffic | ❌ **Not established.** Requires Phase 2 |
| Scores are calibrated probabilities | ❌ **Not claimed.** Requires Phase 3 |
| The platform is production ready | ❌ **Not claimed.** Requires Phase 4 |

---

**Next:** [14 — Security Model](14-security-model.md).
