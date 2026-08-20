"""Train the Android-malware classifier.

Designed for the **Drebin** dataset (it ships pre-extracted feature files, so you don't
have to process thousands of APKs), but works with any directory of per-sample feature
files in the same `type::value` line format.

Usage
-----
  # Real data (Drebin layout):
  python -m app.ml.train --data path/to/feature_vectors \
                         --labels path/to/sha256_family.csv \
                         --out app/ml/model.pkl

  # Smoke-test the whole pipeline with synthetic data (no download needed):
  python -m app.ml.train --demo --out app/ml/model.pkl

Drebin layout expected:
  feature_vectors/<sha256>        one file per sample, lines like 'permission::android.permission.SEND_SMS'
  sha256_family.csv               malicious samples (first column = sha256). Files NOT
                                  listed here are treated as benign.
"""
import argparse
import csv
import io
import os
import random
import sys
import zipfile

from . import features as F


def _load_malware_hashes(labels_path):
    mal = set()
    with open(labels_path, newline="", encoding="utf-8", errors="ignore") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row:
                continue
            h = row[0].strip().lower()
            if h and h != "sha256":
                mal.add(h)
    return mal


def _load_real(data_dir, labels_path):
    mal = _load_malware_hashes(labels_path)
    samples, labels = [], []
    files = [f for f in os.listdir(data_dir) if os.path.isfile(os.path.join(data_dir, f))]
    print(f"Reading {len(files)} feature files from {data_dir} ...")
    for i, fname in enumerate(files):
        try:
            with open(os.path.join(data_dir, fname), encoding="utf-8", errors="ignore") as fh:
                perms = F.perms_from_tokens(fh)
        except Exception:
            continue
        samples.append(perms)
        labels.append(1 if fname.strip().lower() in mal else 0)
        if (i + 1) % 5000 == 0:
            print(f"  ...{i + 1} parsed")
    return samples, labels


MALDROID_CLASS_NAMES = {
    1: "Adware",
    2: "Banking",
    3: "SMS Malware",
    4: "Riskware",
    5: "Benign",
}


def _decode_maldroid_header(value):
    """Decode the UTF-7 fragments used in CICMalDroid's static CSV headers."""
    value = value.strip()
    if "+" not in value:
        return value
    try:
        return value.encode("ascii").decode("utf-7")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value


def _maldroid_permission_columns(header):
    """Map normalized Android permissions to one or more static CSV columns."""
    columns = {}
    for index, raw_name in enumerate(header):
        name = _decode_maldroid_header(raw_name)
        if not name.startswith("android.permission."):
            continue
        short_name = F.short_perm(name)
        if short_name and short_name != "PERMISSION":
            columns.setdefault(short_name, []).append(index)
    return columns


def _feature_present(value):
    value = value.strip()
    if not value:
        return False
    try:
        return float(value) != 0.0
    except ValueError:
        return True


def _load_maldroid(csv_zip):
    """Load live-compatible permission features from the official CSV archive.

    CICMalDroid's static matrix has no class column. The released dynamic matrix has
    the same 11,598-row ordering and supplies numeric classes 1..5. Classes 1..4 are
    malware and class 5 is benign. Dynamic syscall features are deliberately not used
    because the static upload pipeline cannot reproduce them at inference time.
    """
    static_name = "feature_vectors_static.csv"
    labels_name = "feature_vectors_syscallsbinders_frequency_5_Cat.csv"
    samples, labels = [], []
    class_counts = {name: 0 for name in MALDROID_CLASS_NAMES.values()}

    with zipfile.ZipFile(csv_zip) as archive:
        missing = [name for name in (static_name, labels_name) if name not in archive.namelist()]
        if missing:
            raise ValueError(f"CICMalDroid CSV archive is missing: {', '.join(missing)}")
        static_file = io.TextIOWrapper(
            archive.open(static_name), encoding="utf-8-sig", errors="replace", newline=""
        )
        label_file = io.TextIOWrapper(
            archive.open(labels_name), encoding="utf-8-sig", errors="replace", newline=""
        )
        static_reader, label_reader = csv.reader(static_file), csv.reader(label_file)
        static_header, label_header = next(static_reader), next(label_reader)
        if not label_header or label_header[-1].strip().casefold() != "class":
            raise ValueError("CICMalDroid label matrix has no trailing Class column")
        permission_columns = _maldroid_permission_columns(static_header)
        if not permission_columns:
            raise ValueError("No Android permission columns found in static feature matrix")

        for row_index, (static_row, label_row) in enumerate(
            zip(static_reader, label_reader, strict=True)
        ):
            if len(static_row) != len(static_header) or len(label_row) != len(label_header):
                raise ValueError(f"Malformed CICMalDroid CSV row {row_index + 2}")
            class_id = int(float(label_row[-1]))
            if class_id not in MALDROID_CLASS_NAMES:
                raise ValueError(f"Unknown CICMalDroid class {class_id} at row {row_index + 2}")
            perms = {
                permission
                for permission, indices in permission_columns.items()
                if any(_feature_present(static_row[index]) for index in indices)
            }
            samples.append(perms)
            labels.append(0 if class_id == 5 else 1)
            class_counts[MALDROID_CLASS_NAMES[class_id]] += 1

    return samples, labels, class_counts


def _make_demo(n=600):
    """Synthetic dataset to exercise the pipeline without the real dataset.

    Benign: a few common permissions. Malware: SMS/accessibility/overlay-heavy.
    """
    benign_pool = ["INTERNET", "ACCESS_NETWORK_STATE", "VIBRATE", "WAKE_LOCK",
                   "CAMERA", "ACCESS_FINE_LOCATION", "READ_EXTERNAL_STORAGE"]
    mal_pool = ["READ_SMS", "RECEIVE_SMS", "SEND_SMS", "SYSTEM_ALERT_WINDOW",
                "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES",
                "RECEIVE_BOOT_COMPLETED", "READ_CONTACTS", "READ_PHONE_STATE"]
    rng = random.Random(42)
    samples, labels = [], []
    for _ in range(n // 2):
        k = rng.randint(2, 5)
        samples.append(set(rng.sample(benign_pool, k)) | {"INTERNET"})
        labels.append(0)
    for _ in range(n - n // 2):
        k = rng.randint(3, 7)
        s = set(rng.sample(mal_pool, k))
        s |= set(rng.sample(benign_pool, rng.randint(0, 2)))
        samples.append(s)
        labels.append(1)
    return samples, labels


def _build_vocabulary(samples, min_count=3, top_k=400):
    from collections import Counter
    c = Counter()
    for s in samples:
        c.update(s)
    vocab = [perm for perm, cnt in c.most_common() if cnt >= min_count]
    return sorted(vocab[:top_k])


def _select_operating_threshold(y_true, probabilities, min_specificity=0.98):
    """Choose the lowest threshold meeting a benign-specificity safety target."""
    pairs = [(int(label), float(prob)) for label, prob in zip(y_true, probabilities)]
    benign_count = sum(label == 0 for label, _ in pairs)
    if not benign_count:
        return 1.0
    for threshold in sorted({prob for _, prob in pairs}):
        true_negatives = sum(label == 0 and prob < threshold for label, prob in pairs)
        if true_negatives / benign_count >= min_specificity:
            return float(threshold)
    return 1.0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Train Android-malware permission classifier")
    ap.add_argument("--data", help="directory of per-sample feature files (Drebin feature_vectors)")
    ap.add_argument("--labels", help="CSV of malicious sha256s (Drebin sha256_family.csv)")
    ap.add_argument(
        "--maldroid-csv",
        help="official CICMalDroid-2020 CSV.zip; trains on live-compatible static permissions",
    )
    ap.add_argument("--demo", action="store_true", help="train on synthetic data (no dataset needed)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "model.pkl"))
    ap.add_argument("--top-k", type=int, default=400, help="max permissions in the vocabulary")
    args = ap.parse_args(argv)

    selected_modes = sum(bool(value) for value in (args.demo, args.maldroid_csv, args.data))
    if selected_modes != 1:
        ap.error("choose exactly one of --demo, --maldroid-csv, or --data/--labels")

    class_counts = None
    if args.demo:
        print("Building synthetic demo dataset ...")
        samples, labels = _make_demo()
        source = "demo"
    elif args.maldroid_csv:
        print("Reading CICMalDroid static permissions and aligned class labels ...")
        samples, labels, class_counts = _load_maldroid(args.maldroid_csv)
        source = "CICMalDroid-2020 permission features"
        print("Official classes:", ", ".join(f"{k}={v}" for k, v in class_counts.items()))
    else:
        if not args.labels:
            ap.error("--labels is required with --data")
        samples, labels = _load_real(args.data, args.labels)
        source = os.path.basename(args.data.rstrip("/\\"))

    n_pos = sum(labels)
    print(f"Samples: {len(samples)} (malicious={n_pos}, benign={len(labels) - n_pos})")
    if len(set(labels)) < 2:
        sys.exit("Need both benign and malicious samples to train.")

    vocab = _build_vocabulary(samples, top_k=args.top_k)
    print(f"Vocabulary size: {len(vocab)} permissions")

    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, roc_auc_score
    import joblib

    X = np.array([F.vectorize(s, vocab) for s in samples])
    y = np.array(labels)
    X_train_val, X_te, y_train_val, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.2, random_state=43,
        stratify=y_train_val,
    )

    clf = RandomForestClassifier(n_estimators=200, max_depth=None, n_jobs=-1,
                                 class_weight="balanced", random_state=42)
    clf.fit(X_tr, y_tr)

    validation_proba = clf.predict_proba(X_val)[:, 1]
    operating_threshold = _select_operating_threshold(
        y_val, validation_proba, min_specificity=0.98
    )
    proba = clf.predict_proba(X_te)[:, 1]
    pred = (proba >= operating_threshold).astype(int)
    report = classification_report(y_te, pred, target_names=["benign", "malware"], output_dict=True)
    try:
        auc = roc_auc_score(y_te, proba)
    except ValueError:
        auc = None
    print(f"\n=== Evaluation (held-out 20%, threshold={operating_threshold:.4f}) ===")
    print(classification_report(y_te, pred, target_names=["benign", "malware"]))
    if auc is not None:
        print(f"ROC-AUC: {auc:.3f}")

    importances = sorted(
        ({"permission": v, "importance": float(imp)}
         for v, imp in zip(vocab, clf.feature_importances_)),
        key=lambda d: d["importance"], reverse=True,
    )[:25]

    import time
    bundle = {
        "model": clf,
        "vocabulary": vocab,
        "metrics": {
            "precision_malware": report["malware"]["precision"],
            "recall_malware": report["malware"]["recall"],
            "f1_malware": report["malware"]["f1-score"],
            "roc_auc": auc,
            "n_samples": len(samples),
            "n_malicious": int(n_pos),
        },
        "top_features": importances,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "schema_version": 1,
        "feature_kind": "android_permission_multi_hot",
        "operating_threshold": operating_threshold,
        "threshold_policy": {"minimum_benign_specificity": 0.98},
        "class_counts": class_counts,
        "split": {
            "strategy": "stratified_train_validation_test",
            "train_fraction": 0.64,
            "validation_fraction": 0.16,
            "test_fraction": 0.20,
            "random_states": [42, 43],
        },
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    joblib.dump(bundle, args.out)
    print(f"\nSaved model -> {args.out}")
    print("Top permission signals:", ", ".join(d["permission"] for d in importances[:8]))


if __name__ == "__main__":
    main()
