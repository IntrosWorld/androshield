import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import external_tools, runtime_settings
from app.dynamic import adb


class ExternalToolTests(unittest.TestCase):
    def test_selected_adb_wins_and_missing_selection_does_not_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            selected = Path(folder) / "adb.exe"
            selected.touch()
            with patch.dict(os.environ, {"APK_ADB_PATH": str(selected)}, clear=True), \
                 patch.object(external_tools.shutil, "which", return_value="other-adb"):
                self.assertEqual(adb.adb_path(), str(selected))
                selected.unlink()
                self.assertIsNone(adb.adb_path())
                self.assertFalse(external_tools.status()["adb_executable"]["available"])

    def test_relative_paths_resolve_in_portable_data_and_propagate(self):
        with tempfile.TemporaryDirectory() as folder:
            sdk = Path(folder) / "sdk"
            platform = sdk / "platform-tools"
            platform.mkdir(parents=True)
            binary = platform / ("adb.exe" if os.name == "nt" else "adb")
            binary.touch()
            with patch.dict(os.environ, {"APK_DESKTOP_DATA_DIR": folder,
                 "APK_ANDROID_SDK_ROOT": "sdk", "ANDROID_AVD_HOME": "avds",
                 "JAVA_HOME": "java"}, clear=True):
                self.assertEqual(adb.adb_path(), str(binary))
                env = external_tools.subprocess_environment()
                self.assertEqual(env["ANDROID_HOME"], str(sdk))
                self.assertEqual(env["ANDROID_AVD_HOME"], str(Path(folder) / "avds"))
                self.assertEqual(env["JAVA_HOME"], str(Path(folder) / "java"))

    def test_paths_validate_before_save_and_can_be_cleared(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.dict(os.environ, {}, clear=True), \
             patch.object(runtime_settings.db, "save_runtime_settings") as save, \
             patch.object(runtime_settings.db, "delete_runtime_settings"):
            result = runtime_settings.update_settings({"android_sdk_dir": folder})
            self.assertTrue(result["tool_paths"]["android_sdk_dir"]["available"])
            self.assertEqual(save.call_args.args[0]["APK_ANDROID_SDK_ROOT"], (folder, False))
            with self.assertRaises(runtime_settings.SettingsError):
                runtime_settings.update_settings({"adb_executable": folder})
            with self.assertRaises(runtime_settings.SettingsError):
                runtime_settings.update_settings({"android_sdk_dir": str(Path(folder) / "missing")})
            runtime_settings.update_settings({"android_sdk_dir": ""})
            self.assertEqual(os.environ.get("APK_ANDROID_SDK_ROOT", ""), "")


if __name__ == "__main__":
    unittest.main()
