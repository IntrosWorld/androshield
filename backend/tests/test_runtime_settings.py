import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import runtime_settings
from app.main import _require_loopback
from fastapi import HTTPException


class RuntimeSettingsTests(unittest.TestCase):
    def test_machine_settings_reject_non_loopback_clients(self):
        local_request = MagicMock(client=MagicMock(host="127.0.0.1"))
        _require_loopback(local_request)
        remote_request = MagicMock(client=MagicMock(host="192.168.1.25"))
        with self.assertRaises(HTTPException) as context:
            _require_loopback(remote_request)
        self.assertEqual(403, context.exception.status_code)

    def test_update_validates_and_never_returns_secret_values(self):
        saved = {}

        def capture(values):
            saved.update(values)

        with patch.object(runtime_settings.db, "save_runtime_settings", side_effect=capture), \
             patch.object(runtime_settings.db, "delete_runtime_settings"), \
             patch.dict(os.environ, {}, clear=True):
            result = runtime_settings.update_settings({
                "external_api_enabled": True,
                "agent_enabled": True,
                "agent_provider": "ollama",
                "ollama_base_url": "http://127.0.0.1:11434",
                "ollama_model": "qwen3:1.7b",
                "gemini_api_key": "secret-gemini-key",
                "openrouter_api_key": "secret-openrouter-key",
                "openrouter_model": "qwen/qwen3-30b-a3b:free",
            })

        self.assertEqual(("secret-gemini-key", True), saved["GEMINI_API_KEY"])
        self.assertEqual(("secret-openrouter-key", True), saved["OPENROUTER_API_KEY"])
        self.assertTrue(result["gemini_key_configured"])
        self.assertNotIn("gemini_api_key", result)
        self.assertNotIn("secret-gemini-key", str(result))
        self.assertTrue(result["openrouter_key_configured"])
        self.assertNotIn("openrouter_api_key", result)
        self.assertNotIn("secret-openrouter-key", str(result))

    def test_rejects_credentials_in_ollama_url_and_unknown_fields(self):
        for payload in (
            {"ollama_base_url": "http://user:pass@localhost:11434"},
            {"made_up_setting": True},
            {"agent_provider": "opencode"},
        ):
            with self.subTest(payload=payload), self.assertRaises(runtime_settings.SettingsError):
                runtime_settings.update_settings(payload)

    def test_external_services_gate_keys(self):
        with patch.dict(os.environ, {
            "EXTERNAL_API_ENABLED": "false", "GEMINI_API_KEY": "stored",
        }, clear=True):
            result = runtime_settings.public_settings()
        self.assertFalse(result["external_api_enabled"])
        self.assertTrue(result["gemini_key_configured"])

    def test_import_gguf_uses_argument_list_and_selects_model(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "safe model.gguf"
            source.write_bytes(b"GGUF")
            completed = MagicMock(returncode=0, stdout="success", stderr="")
            with patch.object(runtime_settings.shutil, "which", return_value="F:/Ollama/ollama.exe"), \
                 patch.object(runtime_settings.subprocess, "run", return_value=completed) as run, \
                 patch.object(runtime_settings, "update_settings") as update:
                result = runtime_settings.import_gguf(str(source), "android-local:latest")
        command = run.call_args.args[0]
        self.assertEqual("F:/Ollama/ollama.exe", command[0])
        self.assertEqual(["create", "android-local:latest", "--file"], command[1:4])
        self.assertTrue(result["imported"])
        update.assert_called_once_with({"ollama_model": "android-local:latest"})

    def test_import_rejects_non_gguf(self):
        with tempfile.NamedTemporaryFile(suffix=".apk") as source:
            with self.assertRaises(runtime_settings.SettingsError):
                runtime_settings.import_gguf(source.name, "not-an-apk")


if __name__ == "__main__":
    unittest.main()
