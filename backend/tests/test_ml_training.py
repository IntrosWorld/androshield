import csv
import tempfile
import unittest
import zipfile
from pathlib import Path

from app.ml import classifier
from app.ml.train import (
    _decode_maldroid_header,
    _load_maldroid,
    _select_operating_threshold,
)


class MalDroidTrainingTests(unittest.TestCase):
    def test_utf7_permission_header_is_normalized(self):
        self.assertEqual(
            "android.permission.READ_SMS",
            _decode_maldroid_header("android.permission.READ+AF8-SMS"),
        )

    def test_loader_aligns_static_rows_and_binary_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            archive_path = Path(temp) / "CSV.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                static = "index,android.permission.READ+AF8-SMS,android.permission.INTERNET\n0,1,1\n1,,1\n"
                labels = "read,Class\n4,2\n1,5\n"
                archive.writestr("feature_vectors_static.csv", static)
                archive.writestr(
                    "feature_vectors_syscallsbinders_frequency_5_Cat.csv", labels
                )

            samples, labels, counts = _load_maldroid(archive_path)
            self.assertEqual([1, 0], labels)
            self.assertEqual({"READ_SMS", "INTERNET"}, samples[0])
            self.assertEqual({"INTERNET"}, samples[1])
            self.assertEqual(1, counts["Banking"])
            self.assertEqual(1, counts["Benign"])

    def test_operating_threshold_meets_specificity_target(self):
        labels = [0, 0, 0, 0, 1, 1]
        probabilities = [0.1, 0.2, 0.3, 0.7, 0.6, 0.9]
        threshold = _select_operating_threshold(labels, probabilities, min_specificity=0.75)
        specificity = sum(
            label == 0 and probability < threshold
            for label, probability in zip(labels, probabilities)
        ) / 4
        self.assertGreaterEqual(specificity, 0.75)

    def test_below_threshold_prediction_is_not_mislabeled_benign(self):
        class DummyModel:
            def predict_proba(self, _features):
                return [[0.3, 0.7]]

        original = (
            classifier._MODEL_PATH,
            classifier._bundle,
            classifier._load_attempted,
        )
        try:
            classifier._MODEL_PATH = __file__
            classifier._bundle = {
                "model": DummyModel(),
                "vocabulary": ["READ_SMS"],
                "operating_threshold": 0.8,
            }
            classifier._load_attempted = True
            result = classifier.predict({
                "permissions": {"all_permissions": ["android.permission.READ_SMS"]}
            })
            self.assertEqual("not_flagged", result["prediction"])
            self.assertIsNone(result["confidence"])
        finally:
            (
                classifier._MODEL_PATH,
                classifier._bundle,
                classifier._load_attempted,
            ) = original


if __name__ == "__main__":
    unittest.main()
