import unittest

from app.ml.static_features import from_analysis


class StaticMLFeatureTests(unittest.TestCase):
    def test_live_analysis_maps_to_training_schema(self):
        row = from_analysis({
            "manifest": {
                "package_name": "example.app", "min_sdk": "21", "target_sdk": "35",
                "counts": {"activities": 2, "services": 1, "receivers": 3, "providers": 0},
            },
            "permissions": {
                "all_permissions": ["android.permission.INTERNET", "android.permission.READ_SMS"],
                "dangerous": [{"name": "READ_SMS", "score": 12}], "dangerous_count": 1,
            },
            "apis": {"suspicious_apis": [{"api": "SmsManager.sendTextMessage", "score": 12}]},
            "iocs": {"counts": {"urls": 2, "financial_keywords": 1},
                     "financial_keywords": ["otp"], "native_strings_scanned": 9},
            "obfuscation": {"signals": [{"signal": "Dynamic DEX loading", "score": 8}]},
            "yara": {"matches": [{"rule": "SMS_OTP_Stealer", "score": 20}]},
            "apkid": {"findings": [{"category": "Packer", "score": 15}]},
            "certificate": {"present": True, "self_signed": True, "validity_years": 30,
                            "flags": [{"flag": "Debug certificate", "score": 10}]},
            "components": {"count": 4, "unguarded_count": 2},
            "analysis_coverage": {"dex_strings": 200, "dex_control_flow": True},
        })
        self.assertEqual(1.0, row["package_present"])
        self.assertEqual(12, row["dangerous_permission_raw_points"])
        self.assertEqual(1.0, row["perm=READ_SMS"])
        self.assertEqual(1.0, row["dangerous_perm=READ_SMS"])
        self.assertEqual(1.0, row["api=SmsManager.sendTextMessage"])
        self.assertEqual(1.0, row["yara=SMS_OTP_Stealer"])
        self.assertEqual(1.0, row["apkid=Packer"])
        self.assertEqual(1.0, row["financial_keyword=otp"])
        self.assertEqual(9, row["native_string_count"])


if __name__ == "__main__":
    unittest.main()
