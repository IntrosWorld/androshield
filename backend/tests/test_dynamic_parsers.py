import unittest
from unittest.mock import patch

from app.dynamic import adb, frida_runner, sandbox


class DynamicParserTests(unittest.TestCase):
    def test_granted_permissions_parser_is_deduplicated(self):
        text = """
          android.permission.READ_SMS: granted=true
          android.permission.INTERNET: granted=true
          android.permission.READ_SMS: granted=true
          android.permission.CAMERA: granted=false
        """
        self.assertEqual(
            ["READ_SMS", "INTERNET"],
            sandbox.parse_granted_permissions(text),
        )

    def test_network_parser_extracts_runtime_iocs(self):
        text = "connecting to http://steal.example.xyz:8080/c2 from 8.8.8.8"
        result = sandbox.parse_network(text)
        self.assertIn("http://steal.example.xyz:8080/c2", result["urls"])
        self.assertIn("steal.example.xyz", result["domains"])
        self.assertIn("8.8.8.8", result["ips"])

    def test_runtime_signal_parser_reports_behaviour_not_raw_log(self):
        text = "DexClassLoader loaded payload; SmsManager sendTextMessage; Runtime.exec called"
        signals = sandbox.parse_runtime_signals(text)
        self.assertIn("runtime_dex_load", signals)
        self.assertIn("sms_runtime", signals)

    def test_auto_target_never_falls_back_to_arbitrary_device(self):
        devices = [
            {"serial": "emulator-5554", "avd_name": "PersonalPhone"},
            {"serial": "physical-1", "avd_name": None},
        ]
        self.assertIsNone(sandbox._preferred_serial(devices))
        devices.append({"serial": "emulator-5556", "avd_name": sandbox.DEFAULT_SANDBOX_AVD})
        self.assertEqual("emulator-5556", sandbox._preferred_serial(devices))

    def test_dynamic_score_is_capped_and_explainable(self):
        score, breakdown = sandbox.score_dynamic(
            {"urls": ["http://x.xyz/c2"], "domains": ["x.xyz"], "ips": ["8.8.8.8"]},
            ["pkg/.StealService"],
            ["SMS send", "Dynamic code loading", "Shell command"],
            ["android.permission.READ_SMS", "android.permission.RECORD_AUDIO"],
        )
        self.assertLessEqual(score, 100)
        self.assertGreater(score, 0)
        self.assertTrue(all({"category", "points", "detail"} <= set(item) for item in breakdown))

    def test_consent_dismissal_handles_system_ui_wait_dialog(self):
        wait_xml = '<node text="Wait" bounds="[100,200][300,400]" />'
        calls = [
            (0, "", ""), (0, wait_xml, ""), (0, "", ""),
            (0, "", ""), (0, '<hierarchy />', ""),
        ]
        with patch("app.dynamic.adb._run", side_effect=calls) as run:
            with patch("time.sleep"):
                self.assertEqual(["Wait"], adb.dismiss_consent_dialogs("emulator-5554", rounds=2))
        tap = run.call_args_list[2].args[0]
        self.assertEqual(["shell", "input", "tap", "200", "300"], tap)

    def test_legacy_review_preflight_is_force_stopped_before_frida(self):
        triggers = {"target_sdk": 17, "main_activity": "c.l.MainActivity"}
        with patch.object(adb, "launch") as launch, \
                patch.object(adb, "dismiss_consent_dialogs", return_value=["Wait", "Continue"]), \
                patch.object(adb, "force_stop") as force_stop, patch("time.sleep"):
            tapped = frida_runner._prepare_legacy_permission_review(
                "c.l", triggers, "emulator-5554")
        self.assertEqual(["Wait", "Continue"], tapped)
        launch.assert_called_once_with("c.l", "c.l.MainActivity", serial="emulator-5554", timeout=20)
        force_stop.assert_called_once_with("c.l", serial="emulator-5554")

    def test_frida_receiver_triggers_are_async_and_include_sms(self):
        triggers = {
            "receivers": [{"name": "c.l.GPRe", "actions": ["custom.ACTION"]}],
            "services": [],
        }
        with patch.object(adb, "shell") as shell:
            frida_runner._fire_triggers("c.l", triggers, "emulator-5554")
        commands = [call.args[0] for call in shell.call_args_list]
        broadcasts = [cmd for cmd in commands if cmd[:2] == ["am", "broadcast"]]
        self.assertTrue(broadcasts)
        self.assertTrue(all("--async" in cmd for cmd in broadcasts))
        self.assertTrue(any("android.provider.Telephony.SMS_RECEIVED" in cmd for cmd in broadcasts))


if __name__ == "__main__":
    unittest.main()
