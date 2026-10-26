"""Parity checks for the opt-in native experiment, including Python fallbacks."""
import os
import random
import string
import unittest
from unittest.mock import patch

from app.analyzer import iocs, native_accel, obfuscation


def run_mode(mode, function, *args):
    with patch.dict(os.environ, {"ANDROSHIELD_NATIVE": mode}):
        return function(*args)


class NativeFallbackTests(unittest.TestCase):
    def test_benchmark_normalization_does_not_hide_score_or_evidence_changes(self):
        from tools.benchmark_native import comparable
        reference = {"manifest": {"activities": ["B", "A"]}, "risk_score": 10,
                     "ordered_findings": ["first", "second"]}
        reordered = {**reference, "manifest": {"activities": ["A", "B"]}}
        self.assertEqual(comparable(reference), comparable(reordered))
        self.assertNotEqual(comparable(reference), comparable({**reordered, "risk_score": 11}))
        self.assertNotEqual(comparable(reference), comparable({**reordered, "ordered_findings": ["second", "first"]}))

    def test_off_by_default_and_missing_extension_keeps_findings(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(native_accel.enabled())
        sample = ["otp password", "grouping occupied crypto", "UPI UPI", None]
        expected = run_mode("0", iocs.extract_iocs, sample)
        with patch.object(native_accel, "_extension", None):
            self.assertEqual(expected, run_mode("1", iocs.extract_iocs, sample))

    def test_native_exception_falls_back_without_losing_counts(self):
        class Broken:
            def keyword_stats(self, *_):
                raise RuntimeError("test failure")

            def entropy_stats(self, *_):
                raise RuntimeError("test failure")

        strings = ["otp UPI", string.ascii_letters]
        with patch.object(native_accel, "_extension", Broken()), self.assertLogs(native_accel.log, "WARNING"):
            expected = run_mode("0", iocs.extract_iocs, strings)
            self.assertEqual(expected, run_mode("1", iocs.extract_iocs, strings))
            self.assertEqual(run_mode("0", obfuscation.analyze_obfuscation, None, [], strings),
                             run_mode("1", obfuscation.analyze_obfuscation, None, [], strings))


@unittest.skipUnless(native_accel._extension is not None, "build backend/native to test compiled kernels")
class NativeParityTests(unittest.TestCase):
    def assert_modes_equal(self, strings):
        self.assertEqual(run_mode("0", iocs.extract_iocs, strings),
                         run_mode("1", iocs.extract_iocs, strings))
        self.assertEqual(run_mode("0", obfuscation.analyze_obfuscation, None, [], strings),
                         run_mode("1", obfuscation.analyze_obfuscation, None, [], strings))

    def test_word_boundaries_case_unicode_controls_and_lengths(self):
        self.assert_modes_equal([
            "", "otp", "OTP OTP OTP", "grouping occupied crypto", "_otp otp_ otp2 2otp",
            "(cvv) pin/upi credit card", "éotp otpé", "Keylog", "ſecret password", "İFSC ıfsc",
            "密码 otp 🔐", "password\x00otp", "\ud800otp", "\nlogin\tpassword\r",
            "otp" + "." * 3997, "otp" + "." * 3998,
            "https://fixture.invalid/login?password=abcdef123456789",
        ])

    def test_tied_counts_keep_original_first_seen_order(self):
        strings = ["password", "otp", "é login", "credit card", "password otp login credit card"]
        self.assert_modes_equal(strings)
        result = run_mode("1", iocs.extract_iocs, strings)
        self.assertEqual([x["keyword"] for x in result["suspicious_keywords"]],
                         ["password", "otp", "login", "credit card"])

    def test_entropy_threshold_and_candidate_boundaries(self):
        boundary = "abcdefgh" * 2 + "ijklmnopqrstuvwx"
        self.assertEqual(obfuscation._shannon_entropy(boundary), 4.5)
        self.assertIn(0, native_accel._extension.entropy_stats([boundary])[2])
        self.assert_modes_equal([boundary, "a" * 23, "a" * 24, string.ascii_letters,
                                 "a" * 512, "a" * 513, "a " * 40, "密码🔐" * 30])

    def test_seeded_fuzz_matches_full_findings(self):
        rng = random.Random(6781)
        alphabet = string.ascii_letters + string.digits + " _.,:/\n\t\x00éKİ🔐密码"
        strings = ["".join(rng.choices(alphabet, k=rng.randrange(0, 650))) for _ in range(1200)]
        for index in range(0, len(strings), 5):
            strings[index] += " " + rng.choice(iocs.SUSPICIOUS_KEYWORDS).upper()
        self.assert_modes_equal(strings)

    def test_kernel_rejects_unsupported_inputs_and_bounds(self):
        extension = native_accel._extension
        with self.assertRaises(TypeError):
            extension.keyword_stats([b"otp"], ["otp"])
        with self.assertRaises(ValueError):
            extension.keyword_stats(["otp"], [""])
        with self.assertRaises(ValueError):
            extension.entropy_stats([""] * 1000001)
        class CustomString(str):
            def lower(self):
                return "otp"
        self.assert_modes_equal([CustomString("other")])


if __name__ == "__main__":
    unittest.main()
