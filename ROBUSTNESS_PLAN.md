# APKGuard Accuracy and Robustness Plan

This plan separates detector correctness from future model claims. A score is an
explainable triage ranking; it is not a calibrated malware probability until the
evaluation and calibration gates below are completed.

## Phase 1 — Evidence correctness and safety (`exp-2`, implemented)

- Match exact Android methods and require recovered callsites for high-confidence API
  evidence. Keep unresolved DEX references explicit and down-weighted.
- Stop scoring ubiquitous network permissions, ordinary HTTPS links, native libraries,
  generic commerce words, and exported attack surface as independent malware evidence.
- Score higher-risk URLs using visible reasons and DNS-boundary-safe allowlisting.
- Add correlation rules for discriminative fraud chains instead of blindly stacking weak
  signals.
- Cap noisy APKiD anti-VM matches by category.
- Reserve `Confirmed Malicious` for independent multi-engine agreement. Validate and
  normalize all generated-report fields.
- Stream and bound uploads, restrict CORS defaults, validate dynamic device selection,
  and escape untrusted dashboard/PDF content.
- Add fast unit/regression coverage for API evidence, IOCs, risk fusion, verdict policy,
  uploads, PDF generation, dynamic parsers, and sandbox device selection.

Acceptance evidence on the local regression set:

| Sample | Expected role | Before | After |
|---|---|---:|---:|
| Synthetic fraud fixture | Strong suspicious fixture | 100 / Critical | 100 / Critical |
| Packed dropper `.w.apk` | Malicious/dropper regression | Critical | 76 / Critical |
| OpenCalculator | Known benign | 38 / Medium | 17 / Low |
| Outfit7 legacy ad-heavy app | Known benign stress case | 66 / High | 20 / Low |

These four samples are smoke tests, not publishable accuracy evidence.

## Phase 2 — Reproducible evaluation harness

1. Create a hash-only dataset manifest with source, collection date, family/category,
   label provenance, and train/validation/test partition. Never commit raw APKs.
2. Add family-aware de-duplication and temporal splits to prevent campaign leakage.
3. Batch-run the static analyzer into versioned JSON feature records.
4. Report precision, recall, F1, false-positive rate, ROC/PR-AUC, confusion matrices,
   per-family recall, and processing-time percentiles.
5. Tune thresholds only on validation data; lock the final test partition until release.
6. Maintain a modern benign suite containing finance, accessibility, overlay, antivirus,
   VPN, ad-heavy, game, and enterprise-management applications.

Release gate: no detector-weight change without before/after metrics and named regression
cases. Target operating points should be chosen with the bank/SOC team; they must not be
invented from the current demo samples.

## Phase 3 — Calibrated ML corroboration

1. Replace synthetic demo training with versioned real-data training.
2. Keep train/serve features identical. The current Drebin-compatible model should remain
   permission-only until an equivalent live extractor exists for every added feature.
3. Compare logistic regression, Random Forest, and gradient boosting using the same
   partitions and class costs.
4. Calibrate probabilities with Platt or isotonic calibration on validation data only.
5. Add model-card metadata: dataset versions, time range, metrics, limitations, feature
   vocabulary hash, and training-code revision.
6. Refuse to load model bundles that lack schema/version metadata.

Release gate: the ML probability is shown as a probability only after calibration error
and temporal/cross-dataset performance are reported. Until then it remains a labelled
corroborating signal.

## Phase 4 — Dynamic/static fusion and operational hardening

- Persist dynamic runs separately and fuse them only through explicit evidence entries.
- Add interaction scripts, network capture outside logcat, filesystem-delta collection,
  and payload-hash provenance.
- Require authenticated, localhost or isolated-lab access for dynamic execution; add a
  single-run device lock, cancellation, worker timeout, and automatic snapshot restore.
- Run static parsing in resource-limited workers and add request rate limits, structured
  audit logs, retention controls, and database migrations.
- Vendor frontend assets for offline labs and add CI for unit tests, synthetic APK smoke
  analysis, dependency checks, and container builds.

Release gate: threat-model review, recovery test, isolated-network validation, and a
documented operator runbook. The phrase “production ready” should not be used before this
gate is satisfied.
