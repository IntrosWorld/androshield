import unittest

from app.dynamic import sandbox


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


if __name__ == "__main__":
    unittest.main()
