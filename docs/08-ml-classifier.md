# 08 — The ML Classifier

> A deliberately small, deliberately constrained model. Its restraint is the design.

Sources: [`backend/app/ml/`](../backend/app/ml/) — `features.py`, `train.py`, `classifier.py`

---

## 1. The role of ML in this system

Most "AI malware detection" projects put a model at the centre and derive the verdict
from it. This one does the opposite: **the rule engine is the detector; the model is one
capped, thresholded, optional contributor of at most 20 points out of 100.**

Three reasons.

1. **Explainability is a hard requirement.** A bank's fraud desk must be able to justify
   a block. "The gradient boosting ensemble output 0.87" is not a justification.
2. **Android malware datasets age badly.** Drebin is from 2014. A model trained on it
   learns the 2014 threat landscape; a rule engine encoding *mechanisms* (accessibility
   abuse, overlays, OTP interception) generalises far better.
3. **Deployability.** The platform must work with **no model file at all**. `available()`
   returns `False`, the stage is skipped, and nothing else changes.

---

## 2. The feature space, and one non-obvious constraint

Source: [`features.py`](../backend/app/ml/features.py)

The model is trained on **permission multi-hot vectors** and nothing else.

```python
def short_perm(p):          # android.permission.SEND_SMS -> SEND_SMS
    return p.rsplit(".", 1)[-1].strip().upper()

def vectorize(perm_set, vocabulary):
    s = set(perm_set)
    return [1 if v in s else 0 for v in vocabulary]
```

### Why permissions only

Permissions are **the one feature that the training data and the live analyzer express
identically**:

| Side | Source | Normalisation |
|---|---|---|
| Drebin | `permission::android.permission.SEND_SMS` tokens | `perms_from_tokens()` |
| CICMalDroid | `android.permission.*` columns in the static CSV | `_maldroid_permission_columns()` |
| **Live analysis** | `analysis["permissions"]["all_permissions"]` | `perms_from_analysis()` |

All three collapse to the same normalised short name. A model trained on either dataset
applies to live analyzer output **with zero feature drift**.

### Why numeric features were deliberately excluded

The module docstring is explicit about this, and it is the most important ML decision in
the project:

> *Numeric features such as suspicious-API or IOC counts are deliberately omitted: their
> scale differs between Drebin's raw token counts and our matched-label counts, which
> would bias the model.*

Concretely: Drebin's `api_call::` tokens count *every* API reference in the DEX; our
`suspicious_apis` counts *matched labels from a 17-entry curated table*. Both are called
"API count" and they are numerically incomparable — typically differing by orders of
magnitude. A model trained on one and served the other learns a threshold that is
meaningless at inference time, and — worse — **fails silently**. It still produces
confident probabilities; they are simply wrong.

This is training/serving skew, and it is the most common way an ML component quietly
poisons a working system. Extend the feature space **only** with features computable
identically on both sides.

---

## 3. Training

Source: [`train.py`](../backend/app/ml/train.py). Three mutually exclusive modes.

### 3.1 Demo mode — no dataset required

```bash
python -m app.ml.train --demo --out app/ml/model.pkl
```

600 synthetic samples: benign draws from a common-permission pool, malicious draws from
an SMS/accessibility/overlay-heavy pool, seeded (`Random(42)`) for reproducibility. This
exercises the entire pipeline end to end — vocabulary building, split, fit, threshold
selection, metrics, bundle serialisation — without downloading anything.

> Demo mode validates the **plumbing**, never the **accuracy**. A model trained on
> synthetic data separating hand-designed pools tells you nothing about real APKs.

### 3.2 Drebin

```bash
python -m app.ml.train --data path/to/feature_vectors \
                       --labels path/to/sha256_family.csv \
                       --out app/ml/model.pkl
```

One pre-extracted feature file per sample (`type::value` lines) and a CSV of malicious
SHA-256s; files not listed are treated as benign. Drebin ships pre-extracted features, so
no APK processing is needed.

### 3.3 CICMalDroid-2020

```bash
python -m app.ml.train --maldroid-csv path/to/CSV.zip --out app/ml/model.pkl
```

This loader solves a real data-engineering problem, and the details are instructive:

| Problem | Solution |
|---|---|
| The static feature matrix **has no class column** | Labels come from the released dynamic matrix, which shares the same 11 598-row ordering; rows are zipped with `strict=True` so a length mismatch raises instead of silently misaligning |
| Headers contain **UTF-7 fragments** | `_decode_maldroid_header()` decodes `+`-containing headers via `ascii → utf-7` |
| Multiple columns can map to one permission | `permission_columns` is `short_name → [indices]`; a permission is present if **any** mapped column is non-zero |
| Dynamic syscall features are available and tempting | **Deliberately not used** — the static upload pipeline cannot reproduce them at inference time. Using them would be exactly the training/serving skew described in §2 |

Classes 1–4 (Adware, Banking, SMS Malware, Riskware) → label 1; class 5 (Benign) → 0.

---

## 4. Model and split

```python
RandomForestClassifier(n_estimators=200, max_depth=None,
                       n_jobs=-1, class_weight="balanced", random_state=42)
```

| Choice | Why |
|---|---|
| **Random Forest** | Handles sparse binary features natively; gives per-feature importances that map back to named permissions — an interpretable model for an interpretability-first system |
| `class_weight="balanced"` | Real corpora are imbalanced |
| `random_state=42` | Reproducible builds |

### Three-way split

```
100 %  ──▶  80 % train+val  ──▶  64 % train
                             └─▶  16 % validation   ← threshold selection ONLY
       └──▶  20 % test                              ← reported metrics ONLY
```

Stratified at both levels (`random_state` 42 then 43). The separation matters: **the
operating threshold is chosen on validation and evaluated on test.** Choosing a threshold
on the test set would leak, and the reported precision would be optimistic.

### Vocabulary

`_build_vocabulary()` keeps permissions seen ≥3 times, top 400 by frequency, sorted for a
stable column order. It is serialised with the model — inference **must** use the exact
same ordered vocabulary.

---

## 5. Threshold selection: specificity-first

The most consequential line in the training script:

```python
def _select_operating_threshold(y_true, probabilities, min_specificity=0.98):
    """Choose the lowest threshold meeting a benign-specificity safety target."""
    for threshold in sorted({prob for _, prob in pairs}):
        if true_negatives_below(threshold) / benign_count >= min_specificity:
            return float(threshold)
    return 1.0
```

Rather than maximising F1 or accuracy, the threshold is the **lowest value at which at
least 98 % of benign validation samples fall below it**. Recall is whatever that
constraint permits.

### Why optimise specificity instead of accuracy

The operational cost function is asymmetric:

| Error | Cost |
|---|---|
| **False negative** | One malicious sample ranks lower — but the rule engine, YARA, APKiD, and sandbox evidence still score it independently. Optional VirusTotal context is displayed separately and never affects the score. |
| **False positive** | An analyst wastes time on a clean app. Repeated, the tool loses credibility and stops being used at all. |

A triage tool that cries wolf is abandoned, and an abandoned tool has zero recall. **98 %
benign specificity is therefore the binding constraint**, and the policy is recorded in
the bundle as `threshold_policy: {"minimum_benign_specificity": 0.98}` so a future reader
knows the number was a choice, not a default.

If no threshold satisfies the target, the function returns `1.0` — effectively disabling
the classifier rather than shipping one that fires on benign apps. **Failing closed.**

---

## 6. The model bundle

```python
{
  "model": clf,
  "vocabulary": [...],                       # ordered — inference depends on it
  "metrics": {precision_malware, recall_malware, f1_malware, roc_auc,
              n_samples, n_malicious},
  "top_features": [{"permission", "importance"}, ...],   # top 25
  "trained_at": "YYYY-MM-DD HH:MM:SS",
  "source": "CICMalDroid-2020 permission features" | "demo" | "<drebin dir>",
  "schema_version": 1,
  "feature_kind": "android_permission_multi_hot",
  "operating_threshold": 0.83,
  "threshold_policy": {"minimum_benign_specificity": 0.98},
  "class_counts": {"Adware": n, "Banking": n, ...},
  "split": {"strategy": "stratified_train_validation_test",
            "train_fraction": 0.64, "validation_fraction": 0.16,
            "test_fraction": 0.20, "random_states": [42, 43]},
}
```

The bundle is **self-describing provenance**. Anyone holding a `model.pkl` can recover
what it was trained on, how it was split, what threshold policy produced its operating
point, and what it scored — without the training environment. For a security artefact
that is not documentation polish; it is what makes a result reproducible and auditable.

`model.pkl` is git-ignored (`*.pkl`) — models are never committed.

---

## 7. Inference

Source: [`classifier.py`](../backend/app/ml/classifier.py)

```python
def available():
    if not os.path.exists(_MODEL_PATH): return False
    return _load() is not None            # lazy, cached, single attempt
```

Loading is lazy, attempted once (`_load_attempted`), and any failure is logged and
degrades to unavailable. A corrupt or version-mismatched pickle disables ML; it does not
break analysis.

### Output

```json
{
  "available": true,
  "malware_probability": 0.9134,
  "prediction": "flagged",
  "decision_threshold": 0.83,
  "confidence": 0.9134,
  "contributing_permissions": [{"permission": "RECEIVE_SMS", "importance": 0.081}, ...],
  "model_metrics": {...},
  "trained_at": "2026-03-11 09:22:14"
}
```

### Two deliberate asymmetries in the wording

**(a) `"flagged"` / `"not_flagged"`, never `"benign"`.** The comment is explicit:

> *Below a conservative alert threshold means "no ML alert", not proof that an APK is
> benign. Other static evidence can still establish high risk.*

**(b) `confidence` is `None` when not flagged.** There is no such thing as "91 % confident
this is clean" from this model. The field is absent rather than misleadingly present.

### `contributing_permissions`

The top-25 importance list is intersected with the permissions actually present in *this*
sample, capped at 8. The report can then say *"the model responded to RECEIVE_SMS,
BIND_ACCESSIBILITY_SERVICE, and SYSTEM_ALERT_WINDOW"* rather than presenting a bare
number. Even the ML layer explains itself.

---

## 8. Fusion into the score

See [05 §7](05-risk-scoring.md#7-ml-fusion).

```python
if prob >= threshold and prediction in ("flagged", "malware"):
    points = min(round(prob * 20), 20)
```

At the 20-point cap the model can move a sample **at most one severity band**. A sample
at 55 (High) with a 100 %-confident model reaches 75 (Critical); a sample at 10 (Low)
reaches 30 (Medium). The model can escalate attention. It cannot manufacture a verdict.

---

## 9. Honest limitations

| Limitation | Status |
|---|---|
| Permissions alone are a **weak** feature space | Accepted — this is a corroborating signal, never a detector |
| Drebin (2014) does not represent current malware | Prefer CICMalDroid; treat any Drebin model as a demo |
| No family-aware de-duplication or temporal splits yet | Documented as Phase 2 in [ROBUSTNESS_PLAN.md](../ROBUSTNESS_PLAN.md); random splits can leak campaigns across train/test and inflate metrics |
| A dropper declaring almost nothing is invisible here | By construction — that is what the correlation rules and dynamic analysis are for |
| Reported metrics are dataset metrics | They do **not** transfer to production traffic; see [13 — Evaluation](13-evaluation-and-accuracy.md) |

---

## 10. Recipes

```bash
# Pipeline smoke test, no dataset
python -m app.ml.train --demo --out app/ml/model.pkl

# CICMalDroid-2020 (recommended)
python -m app.ml.train --maldroid-csv /data/CSV.zip --out app/ml/model.pkl

# Drebin
python -m app.ml.train --data /data/feature_vectors \
                       --labels /data/sha256_family.csv --out app/ml/model.pkl

# Verify it loaded
curl http://localhost:8000/api/health     # -> "ml_model_loaded": true

# Disable ML entirely
rm backend/app/ml/model.pkl
```

Tests: `backend/tests/test_ml_training.py`.

---

**Next:** [09 — Dynamic Analysis](09-dynamic-analysis.md).
