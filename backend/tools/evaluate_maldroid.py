"""Evaluate the static analyzer against an extracted CICMalDroid-2020 corpus.

The evaluator never installs or executes an APK. It recursively discovers APKs under
the supplied dataset directory, derives the official five-class label from directory
names, runs the existing static analyzer, and writes transparent binary/per-class
metrics. MalDroid's four non-benign classes are treated as positive for the binary
fraud/malware triage metrics.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from statistics import mean

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.analyzer.static_analyzer import analyze  # noqa: E402


CLASSES = ("Adware", "Banking", "SMS Malware", "Riskware", "Benign")
_LABEL_ALIASES = {
    "adware": "Adware",
    "banking": "Banking",
    "bankingmalware": "Banking",
    "sms": "SMS Malware",
    "smsmalware": "SMS Malware",
    "riskware": "Riskware",
    "mobileriskware": "Riskware",
    "benign": "Benign",
}


def _normalise_component(value: str) -> str:
    return "".join(ch for ch in value.casefold() if ch.isalnum())


def infer_label(path: Path, dataset_root: Path) -> str | None:
    """Infer an official MalDroid class from a path component, never filename text."""
    try:
        relative = path.resolve().relative_to(dataset_root.resolve())
    except ValueError:
        relative = path
    for part in reversed(relative.parts[:-1]):
        label = _LABEL_ALIASES.get(_normalise_component(part))
        if label:
            return label
    return None


def discover_apks(dataset_root: Path) -> tuple[dict[str, list[Path]], list[Path]]:
    grouped: dict[str, list[Path]] = {label: [] for label in CLASSES}
    unknown = []
    for path in sorted(dataset_root.rglob("*.apk")):
        label = infer_label(path, dataset_root)
        if label:
            grouped[label].append(path)
        else:
            unknown.append(path)
    return grouped, unknown


def select_stratified(
    grouped: dict[str, list[Path]], limit_per_class: int, seed: int
) -> list[tuple[str, Path]]:
    """Return a deterministic, class-balanced subset (or every APK when limit is 0)."""
    selected = []
    for index, label in enumerate(CLASSES):
        paths = list(grouped.get(label, []))
        if limit_per_class and len(paths) > limit_per_class:
            random.Random(seed + index).shuffle(paths)
            paths = sorted(paths[:limit_per_class])
        selected.extend((label, path) for path in paths)
    return selected


def compute_metrics(rows: list[dict], threshold: int) -> dict:
    valid = [row for row in rows if row.get("valid_apk") and row.get("score") is not None]
    tp = tn = fp = fn = 0
    per_class = {}
    for row in valid:
        expected_positive = row["label"] != "Benign"
        predicted_positive = row["score"] >= threshold
        if expected_positive and predicted_positive:
            tp += 1
        elif expected_positive:
            fn += 1
        elif predicted_positive:
            fp += 1
        else:
            tn += 1

    def ratio(numerator: int, denominator: int) -> float:
        return round(numerator / denominator, 4) if denominator else 0.0

    for label in CLASSES:
        class_rows = [row for row in valid if row["label"] == label]
        flagged = sum(row["score"] >= threshold for row in class_rows)
        per_class[label] = {
            "analyzed": len(class_rows),
            "flagged": flagged,
            "flag_rate": ratio(flagged, len(class_rows)),
            "average_score": round(mean(row["score"] for row in class_rows), 2)
            if class_rows
            else 0.0,
        }

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "threshold": threshold,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": ratio(tp + tn, tp + tn + fp + fn),
        "precision": precision,
        "recall": recall,
        "specificity": ratio(tn, tn + fp),
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0,
        "per_class": per_class,
        "valid_samples": len(valid),
        "full_samples": sum(row.get("analysis_quality", "full") == "full" for row in valid),
        "partial_samples": sum(row.get("analysis_quality") == "partial" for row in valid),
        "failed_samples": len(rows) - len(valid),
    }


def analyze_sample(path: Path, label: str) -> dict:
    started = time.perf_counter()
    try:
        result = analyze(str(path))
        return {
            "path": str(path),
            "filename": path.name,
            "label": label,
            "valid_apk": result.get("valid_apk", False),
            "analysis_quality": result.get("analysis_quality", "failed"),
            "sha256": result.get("file", {}).get("sha256", ""),
            "package_name": result.get("manifest", {}).get("package_name", ""),
            "score": result.get("risk_score"),
            "severity": result.get("severity", "Unknown"),
            "dangerous_permissions": result.get("permissions", {}).get("dangerous_count", 0),
            "suspicious_apis": result.get("apis", {}).get("count", 0),
            "yara_matches": [m.get("rule", "") for m in result.get("yara", {}).get("matches", [])],
            "errors": result.get("errors", []),
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }
    except Exception as exc:  # one malformed sample must not abort a corpus run
        return {
            "path": str(path),
            "filename": path.name,
            "label": label,
            "valid_apk": False,
            "analysis_quality": "failed",
            "sha256": "",
            "package_name": "",
            "score": None,
            "severity": "Unknown",
            "dangerous_permissions": 0,
            "suspicious_apis": 0,
            "yara_matches": [],
            "errors": [f"Evaluator failure: {exc}"],
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }


def write_rows_csv(path: Path, rows: list[dict]) -> None:
    columns = (
        "path", "filename", "label", "valid_apk", "analysis_quality", "sha256", "package_name",
        "score", "severity", "dangerous_permissions", "suspicious_apis",
        "yara_matches", "errors", "elapsed_seconds",
    )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            output = dict(row)
            output["yara_matches"] = ";".join(output["yara_matches"])
            output["errors"] = ";".join(output["errors"])
            writer.writerow(output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True, help="Extracted MalDroid root")
    parser.add_argument(
        "--limit-per-class", type=int, default=25,
        help="Deterministic sample count per class; 0 analyzes the entire corpus (default: 25)",
    )
    parser.add_argument("--seed", type=int, default=2020)
    parser.add_argument(
        "--threshold", type=int, default=21,
        help="Minimum rule score considered flagged (default: 21 / Medium)",
    )
    parser.add_argument(
        "--output", type=Path, default=BACKEND_ROOT / "data" / "evaluations" / "maldroid",
        help="Output directory for summary.json and samples.csv",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.dataset.is_dir():
        raise SystemExit(f"Dataset directory does not exist: {args.dataset}")
    if args.limit_per_class < 0:
        raise SystemExit("--limit-per-class must be 0 or greater")
    if not 0 <= args.threshold <= 100:
        raise SystemExit("--threshold must be between 0 and 100")

    # Androguard uses loguru and is extremely verbose at DEBUG in batch runs.
    try:
        from loguru import logger
        logger.remove()
    except Exception:
        pass
    logging.disable(logging.CRITICAL)

    grouped, unknown = discover_apks(args.dataset)
    selected = select_stratified(grouped, args.limit_per_class, args.seed)
    if not selected:
        raise SystemExit(
            "No labeled APKs found. Expected APKs beneath Adware, Banking, SMS Malware, "
            "Riskware, or Benign directories."
        )

    rows = []
    for index, (label, path) in enumerate(selected, start=1):
        print(f"[{index}/{len(selected)}] {label}: {path.name}", flush=True)
        rows.append(analyze_sample(path, label))

    args.output.mkdir(parents=True, exist_ok=True)
    metrics = compute_metrics(rows, args.threshold)
    summary = {
        "dataset": "CICMalDroid-2020",
        "dataset_root": str(args.dataset.resolve()),
        "selection": {
            "seed": args.seed,
            "limit_per_class": args.limit_per_class,
            "discovered": {label: len(grouped[label]) for label in CLASSES},
            "selected": dict(
                (label, sum(row["label"] == label for row in rows)) for label in CLASSES
            ),
            "unlabeled_apks_skipped": len(unknown),
        },
        "metrics": metrics,
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    write_rows_csv(args.output / "samples.csv", rows)
    print(json.dumps(metrics, indent=2))
    print(f"Results written to {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
