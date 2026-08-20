import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.sample_maldroid_archive import safe_apk_name, sample_archive


class MalDroidArchiveSamplerTests(unittest.TestCase):
    def test_rejects_traversal_links_and_non_hash_names(self):
        regular = tarfile.TarInfo("Benign/" + "a" * 64 + ".apk")
        regular.size = 1
        self.assertEqual("a" * 64 + ".apk", safe_apk_name(regular, "Benign"))

        for name in ("../Benign/" + "a" * 64 + ".apk", "Benign/app.apk", "Banking/" + "a" * 64 + ".apk"):
            member = tarfile.TarInfo(name)
            member.size = 1
            self.assertIsNone(safe_apk_name(member, "Benign"))
        link = tarfile.TarInfo("Benign/" + "b" * 64 + ".apk")
        link.type = tarfile.SYMTYPE
        self.assertIsNone(safe_apk_name(link, "Benign"))

    def test_streaming_sample_stops_at_requested_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "Benign.tar.gz"
            payloads = [b"first apk", b"second apk", b"third apk"]
            with tarfile.open(archive, "w:gz") as tar:
                for payload in payloads:
                    digest = hashlib.sha256(payload).hexdigest()
                    member = tarfile.TarInfo(f"Benign/{digest}.apk")
                    member.size = len(payload)
                    tar.addfile(member, io.BytesIO(payload))

            output = root / "sample"
            rows = sample_archive(archive, output, class_name="Benign", count=2)
            self.assertEqual(2, len(rows))
            self.assertEqual(2, len(list(output.glob("*.apk"))))
            manifest = json.loads((output / "sample_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(2, manifest["extracted"])


if __name__ == "__main__":
    unittest.main()
