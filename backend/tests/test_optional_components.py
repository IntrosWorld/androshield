import lzma
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import optional_components


class _DownloadResponse:
    def __init__(self, data: bytes):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit=-1):
        return self.data


class OptionalComponentTests(unittest.TestCase):
    def test_catalog_uses_allowlisted_official_sources(self):
        with patch.object(optional_components, "_ollama_models", return_value={"qwen3:1.7b"}), \
             patch.object(optional_components.shutil, "which", return_value="ollama"), \
             patch.object(optional_components, "_sdk_root", return_value=None), \
             patch.object(optional_components, "_frida_version", return_value="16.7.19"):
            catalog = optional_components.component_catalog()
        ids = {item["id"] for item in catalog["components"]}
        self.assertEqual(
            {"agent-model-fast", "agent-model-quality", "android-sandbox", "frida-server"},
            ids,
        )
        self.assertFalse(catalog["research_datasets_included"])
        for item in catalog["components"]:
            self.assertTrue(item["source_url"].startswith("https://"))

    def test_model_install_uses_ollama_argument_list_and_selects_model(self):
        completed = MagicMock(returncode=0, stdout="success", stderr="")
        with patch.object(optional_components.shutil, "which", return_value="F:/Ollama/ollama.exe"), \
             patch.object(optional_components.subprocess, "run", return_value=completed) as run, \
             patch("app.runtime_settings.update_settings") as update:
            optional_components._run_model_install("job", "agent-model-fast")
        self.assertEqual(
            ["F:/Ollama/ollama.exe", "pull", "qwen3:1.7b"], run.call_args.args[0],
        )
        update.assert_called_once_with({"ollama_model": "qwen3:1.7b"})

    def test_frida_download_is_bounded_decompressed_and_cached(self):
        payload = b"frida-binary"
        response = _DownloadResponse(lzma.compress(payload))
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(optional_components, "_frida_version", return_value="16.7.19"), \
             patch.object(optional_components, "_frida_cache_path", return_value=Path(folder) / "frida-server"), \
             patch.object(optional_components.urllib.request, "urlopen", return_value=response):
            optional_components._run_frida_install("job")
            self.assertEqual(payload, (Path(folder) / "frida-server").read_bytes())

    def test_unknown_component_is_rejected_before_a_job_starts(self):
        with self.assertRaises(optional_components.ComponentError):
            optional_components.start_install("arbitrary-url")


if __name__ == "__main__":
    unittest.main()
