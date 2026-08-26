import csv
import gzip
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.tools import androzoo_pipeline as az


FIELDS = [
    "sha256", "sha1", "md5", "dex_date", "apk_size", "pkg_name", "vercode",
    "vt_detection", "vt_scan_date", "dex_size", "markets",
]


def metadata_row(sha_char, package, vt, market, scan="2025-01-02", size="1000000"):
    return {
        "sha256": sha_char * 64, "sha1": "", "md5": "", "dex_date": "2024-01-01",
        "apk_size": size, "pkg_name": package, "vercode": "1",
        "vt_detection": str(vt), "vt_scan_date": scan, "dex_size": "500000",
        "markets": market,
    }


class AndroZooPipelineTests(unittest.TestCase):
    def test_key_loads_from_env_file_without_exposing_value(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {}, clear=True):
            env_file = Path(temp) / ".env"
            env_file.write_text("ANDROZOO_API_KEY=private-test-key\n", encoding="utf-8")
            self.assertEqual("private-test-key", az.load_api_key(env_file))

    def test_selection_is_balanced_deterministic_and_package_disjoint(self):
        rows = [
            metadata_row("A", "good.one", 0, "play.google.com"),
            metadata_row("B", "good.one", 0, "play.google.com"),
            metadata_row("C", "good.two", 0, "play.google.com|fdroid"),
            metadata_row("D", "bad.one", 18, "appchina"),
            metadata_row("E", "bad.two", 25, "play.google.com"),
            metadata_row("F", "too.old", 0, "play.google.com", scan="2019-01-01"),
        ]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            metadata = root / "latest.csv.gz"
            with gzip.open(metadata, "wt", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows(rows)
            first = root / "manifest-one.csv"
            second = root / "manifest-two.csv"
            selected = az.select_manifest(metadata, first, 2, 2, seed=77)
            az.select_manifest(metadata, second, 2, 2, seed=77)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(4, len(selected))
            self.assertEqual(4, len({row["pkg_name"] for row in selected}))
            self.assertEqual({"benign_candidate", "likely_malicious"},
                             {row["label"] for row in selected})

    @patch("backend.tools.androzoo_pipeline.urllib.request.urlopen")
    def test_apk_download_requires_expected_hash_and_size(self, urlopen):
        apk = b"PK\x03\x04" + b"safe-test-archive"
        sha256 = hashlib.sha256(apk).hexdigest().upper()
        urlopen.return_value = io.BytesIO(apk)
        row = {"sha256": sha256, "apk_size": str(len(apk)), "label": "benign_candidate"}
        with tempfile.TemporaryDirectory() as temp:
            result = az._download_one(row, Path(temp), "hidden-key", retries=0)
            self.assertEqual("downloaded and verified", result[1])
            saved = Path(temp) / "benign_candidate" / f"{sha256}.apk"
            self.assertEqual(apk, saved.read_bytes())


if __name__ == "__main__":
    unittest.main()
