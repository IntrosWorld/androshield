# CICMalDroid-2020 evaluation

The project supports reproducible, static-only evaluation against the official
[CICMalDroid-2020 dataset](https://www.unb.ca/cic/datasets/maldroid-2020.html).
The dataset contains 17,341 APKs across Adware, Banking malware, SMS malware,
Riskware, and Benign classes. CIC reports 11,598 usable labeled analysis records.

## Obtain the dataset

Use CIC's official **Download the dataset** link and complete its registration form
with your own details. Direct file browsing is access-controlled. Do not commit the
downloaded archives or APKs; `*.apk` and `samples/` are ignored by this repository.

Extract the APK portion so the five official class names appear somewhere in the
directory hierarchy. The evaluator recognizes `Adware`, `Banking`/`Banking Malware`,
`SMS`/`SMS Malware`, `Riskware`, and `Benign` directory components.

## Run a bounded calibration

From `backend/`:

```powershell
.\.venv\Scripts\python.exe tools\evaluate_maldroid.py `
  --dataset "F:\datasets\CICMalDroid-2020" `
  --limit-per-class 25 `
  --seed 2020
```

This analyzes at most 125 APKs and writes `summary.json` plus per-sample
`samples.csv` under `backend/data/evaluations/maldroid/`. That output is ignored by
Git. Use `--limit-per-class 0` only after the bounded run succeeds; analyzing the full
17,341-APK corpus can take many hours.

The default decision threshold is 21 (`Medium` or above). The report includes a
binary confusion matrix, accuracy, precision, recall, specificity, F1, parse failures,
and per-class flag rates. Adware, Banking, SMS Malware, and Riskware are positive;
Benign is negative. Because the platform produces malware-risk scores rather than
five-family classification, per-class flag rate is reported instead of pretending it
predicts a malware family.

For a very large class archive, extract only a bounded, hash-verified stream sample:

```powershell
.\.venv\Scripts\python.exe tools\sample_maldroid_archive.py `
  "F:\datasets\Benign.tar.gz" "F:\datasets\benign-sample" `
  --class-name Benign --count 20 --max-total-mb 500
```

The sampler accepts only regular `Class/<sha256>.apk` members, verifies each APK against
its hash filename, enforces per-file and total-byte limits, and stops reading the archive
after the requested count. Use `--skip N` to create later calibration batches without
extracting the skipped files. A first-N or skipped batch is convenient development data,
not a random or independently representative test set.

## Safety and interpretation

- The evaluator calls only the static analyzer. It never installs or executes APKs.
- Store the corpus outside the repository and do not open samples manually.
- Treat parse failures as coverage gaps, not benign predictions.
- A malformed DEX falls back to bounded manifest and raw-string analysis. Such results
  are labeled `partial`; low/medium partial results remain `Inconclusive` rather than
  being presented as clean.
- Tune rules on a calibration subset and report final metrics on a separate held-out
  subset to avoid overfitting.
- Cite the dataset papers listed on CIC's dataset page in any publication or submission.

## Local Banking archive run (2026-08-15)

The supplied `Banking.tar.gz` contained 2,505 APK members (2,507 total archive
members), 4,166,138,748 uncompressed bytes, and no archive path traversal or link
entries. Its SHA-256 is
`353c9d800ad73b0048fe6d7f8649008c30b6d776c68137041c0be9fc1258ffa7`.
Windows Defender blocked/quarantined some extracted samples; security controls were not
disabled or bypassed.

A deterministic 25-sample run over the currently available 2,502 Banking APKs produced:

| Coverage/result | Count |
|---|---:|
| Full DEX analysis | 22 |
| Partial manifest/raw-string fallback | 3 |
| Failed analysis | 0 |
| Flagged at score >= 21 | 21 |
| Below threshold | 4 |

This Banking-only flag rate is 84%, not a complete accuracy measurement: without the
Benign archive, false-positive rate, specificity, and balanced accuracy cannot be
measured. On the six malformed samples from the earlier baseline, the fallback recovered
all six as partial results and flagged five (scores 83-98); the remaining score-9 sample
is reported as `Inconclusive`.

## CSV utilization and ML baseline

The official `CSV.zip` was validated and consumed directly without extracting its
595 MB static matrix. It contains 11,598 aligned samples:

| Numeric class | Official category | Rows |
|---:|---|---:|
| 1 | Adware | 1,253 |
| 2 | Banking | 2,100 |
| 3 | SMS Malware | 3,904 |
| 4 | Riskware | 2,546 |
| 5 | Benign | 1,795 |

The deployable classifier uses 206 permission features selected from the 50,621-column
static matrix. It intentionally excludes the 139 syscall and 470 syscall/Binder runtime
features because static APK analysis cannot reproduce them at inference time.

The permission RandomForest uses separate stratified train (64%), validation (16%), and
test (20%) partitions. The validation set selected a conservative 0.7277 alert threshold
targeting at least 98% benign specificity. On the untouched row-level test partition it
produced ROC-AUC 0.989, 97% benign recall/specificity, and 93% malware recall. The model
reports `not_flagged`, never `benign`, below the threshold. Independent benign controls
remained Low with zero ML score contribution. These figures remain development evidence
because the released matrix lacks hashes required for campaign de-duplication and a
temporal split.

On the same current 25-APK Banking batch, conservative ML corroboration raised the flag
count from 21 to 24 while all 25 analyses completed (22 full, 3 partial). The result
remained 24/25 after calibrating generic permissions, YARA rules, API evidence, multi-DEX,
and anti-debug findings against four additional F-Droid benign stress cases. This is an
integration regression result, not independent validation, because CICMalDroid CSV rows
supplied the training corpus and cannot be hash-matched to exclude overlap.

## Partial Benign archive run (2026-08-17)

The supplied `Benign.tar.gz` is 51,040,876,727 bytes (47.54 GiB), larger than the free
space available for full extraction. A bounded first-20 slice was therefore extracted to
`test/a/benign_sample_first20/Benign`: 20 hash-named APKs totaling 289,273,595 bytes
(275.87 MiB). All 20 completed full static analysis; none was installed or executed.

Before the benign-driven calibration, 19/20 scored at least 21 (5% specificity; average
benign score 46.5). Inspection found systematic double/triple counting from broad
permission sets, library-only `DexClassLoader` calls, uncorroborated notification-listener
use, and generic Internet capability. After applying contextual/diminishing scoring, the
same slice flagged 8/20 (60% specificity; average score 24.55).

On the deterministic 25 Banking APK regression set, the calibrated analyzer flagged
22/25 (88% recall; average score 71.56), with 22 full and 3 partial analyses and no
failures. Two of the new below-threshold samples had previously crossed the threshold
almost entirely through Google-library dynamic-loader signals; retaining those points
would knowingly restore a false-positive mechanism. Combined 45-sample results are in
`backend/data/evaluations/maldroid_banking25_benign20_recalibrated/`.

These numbers are calibration evidence only. The first 20 archive entries are neither
random nor held out, and the deployed ML model was trained on CIC's released feature
matrix. A separate immutable benign batch (preferably package-disjoint and independently
sourced) is required before reporting final accuracy.

## Additional dataset strategy

### AndroZoo — recommended independent benign source

Use [AndroZoo](https://androzoo.uni.lu/) for a modern, hash-pinned benign test partition once institutional access is
approved. Select one APK per package from `play.google.com`, require `vt_detection=0`,
record `vt_scan_date`, and prefer recent scans. A zero VirusTotal count is a useful
selection rule, not proof of benignness; manually review outliers and keep the final hash
manifest immutable. Never train on the same package families used for the final test.

AndroZoo requires a personal API key requested from an institutional email, prohibits key
sharing/redistribution/commercial use, and downloads APKs by SHA-256. No key is configured
in this workspace, so no AndroZoo APKs have been downloaded.

### Drebin — malware recall/cross-dataset test

[Drebin](https://drebin.mlsec.org/) contains 5,560 malware APKs from 179 families collected in 2010–2012. It is useful
for testing recall on older families and for the existing permission-feature trainer, but
it is not a benign corpus and is too old to be the sole production-training source.
Official access requires an identity/research-scope request (students apply through an
advisor). Keep Drebin as a separate cross-dataset evaluation instead of mixing it into the
CICMalDroid held-out result.
