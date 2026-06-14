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
import os
import random
import sys

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


def main(argv=None):
    ap = argparse.ArgumentParser(description="Train Android-malware permission classifier")
    ap.add_argument("--data", help="directory of per-sample feature files (Drebin feature_vectors)")
    ap.add_argument("--labels", help="CSV of malicious sha256s (Drebin sha256_family.csv)")
    ap.add_argument("--demo", action="store_true", help="train on synthetic data (no dataset needed)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "model.pkl"))
    ap.add_argument("--top-k", type=int, default=400, help="max permissions in the vocabulary")
    args = ap.parse_args(argv)

    if args.demo:
        print("Building synthetic demo dataset ...")
        samples, labels = _make_demo()
    else:
        if not args.data or not args.labels:
            ap.error("--data and --labels are required unless --demo is set")
        samples, labels = _load_real(args.data, args.labels)

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
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=200, max_depth=None, n_jobs=-1,
                                 class_weight="balanced", random_state=42)
    clf.fit(X_tr, y_tr)

    proba = clf.predict_proba(X_te)[:, 1]
    pred = (proba >= 0.5).astype(int)
    report = classification_report(y_te, pred, target_names=["benign", "malware"], output_dict=True)
    try:
        auc = roc_auc_score(y_te, proba)
    except ValueError:
        auc = None
    print("\n=== Evaluation (held-out 20%) ===")
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
        "source": "demo" if args.demo else os.path.basename(args.data.rstrip("/\\")),
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    joblib.dump(bundle, args.out)
    print(f"\nSaved model -> {args.out}")
    print("Top permission signals:", ", ".join(d["permission"] for d in importances[:8]))


if __name__ == "__main__":
    main()
