import tempfile
import unittest
from pathlib import Path

from tools.evaluate_maldroid import compute_metrics, discover_apks, infer_label, select_stratified


class MalDroidEvaluatorTests(unittest.TestCase):
    def test_label_inference_uses_official_class_directories(self):
        root = Path("dataset")
        self.assertEqual("Banking", infer_label(root / "Banking Malware" / "a.apk", root))
        self.assertEqual("SMS Malware", infer_label(root / "SMS Malware" / "b.apk", root))
        self.assertEqual("Benign", infer_label(root / "Benign" / "c.apk", root))
        self.assertIsNone(infer_label(root / "unknown" / "riskware-looking-name.apk", root))

    def test_discovery_and_stratified_selection_are_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for label in ("Adware", "Banking", "SMS Malware", "Riskware", "Benign"):
                folder = root / label
                folder.mkdir()
                for index in range(3):
                    (folder / f"{index}.apk").touch()
            (root / "Unknown").mkdir()
            (root / "Unknown" / "x.apk").touch()

            grouped, unknown = discover_apks(root)
            selected = select_stratified(grouped, limit_per_class=2, seed=2020)
            self.assertEqual(10, len(selected))
            self.assertEqual(1, len(unknown))
            self.assertEqual(selected, select_stratified(grouped, 2, 2020))

    def test_metrics_exclude_parse_failures_and_report_false_positives(self):
        rows = [
            {"label": "Banking", "valid_apk": True, "score": 80},
            {"label": "SMS Malware", "valid_apk": True, "score": 10},
            {"label": "Benign", "valid_apk": True, "score": 30},
            {"label": "Benign", "valid_apk": True, "score": 5},
            {"label": "Riskware", "valid_apk": False, "score": None},
        ]
        metrics = compute_metrics(rows, threshold=21)
        self.assertEqual({"tp": 1, "tn": 1, "fp": 1, "fn": 1}, metrics["confusion_matrix"])
        self.assertEqual(4, metrics["valid_samples"])
        self.assertEqual(1, metrics["failed_samples"])
        self.assertEqual(0.5, metrics["f1"])


if __name__ == "__main__":
    unittest.main()
