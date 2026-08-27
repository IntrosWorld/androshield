import asyncio
import hashlib
import os
import re
import tempfile
import time
import unittest
from io import BytesIO
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException, UploadFile
from app.analyzer import api_patterns, iocs, permissions, risk_scoring, static_analyzer, yara_scan
from app.genai.gemini_client import _evidence_assessment, _normalise_report, _template_report
from app import main, report as report_pdf


class _Caller:
    def __init__(self, class_name="Lcom/example/App;", name="run"):
        self.class_name = class_name
        self.name = name


class _Method:
    def __init__(self, class_name, name, called=True):
        self.class_name = class_name
        self.name = name
        self.called = called

    def get_xref_from(self):
        return [(None, _Caller(), None)] if self.called else []


class _Analysis:
    def __init__(self, methods):
        self.methods = methods

    def find_methods(self, classname=".*", methodname=".*", **_kwargs):
        class_rx = re.compile(classname)
        method_rx = re.compile(methodname)
        return [
            m for m in self.methods
            if class_rx.search(m.class_name) and method_rx.search(m.name)
        ]


def _empty_iocs(urls=()):
    return iocs.extract_iocs(list(urls))


class ApiAccuracyTests(unittest.TestCase):
    def test_generic_runtime_use_is_not_mislabeled_as_exec(self):
        dx = _Analysis([_Method("Ljava/lang/Runtime;", "getRuntime")])
        result = api_patterns.analyze_apis(dx, ["Ljava/lang/Runtime;", "getRuntime"])
        self.assertNotIn("Runtime.exec", {f["api"] for f in result["suspicious_apis"]})

    def test_exact_runtime_exec_call_is_high_confidence(self):
        dx = _Analysis([_Method("Ljava/lang/Runtime;", "exec")])
        result = api_patterns.analyze_apis(dx, [])
        finding = next(f for f in result["suspicious_apis"] if f["api"] == "Runtime.exec")
        self.assertEqual("invoked", finding["evidence_type"])
        self.assertEqual("high", finding["confidence"])
        self.assertEqual(3, finding["score"])

    def test_reference_only_capability_is_explicit_and_downweighted(self):
        result = api_patterns.analyze_apis(
            _Analysis([]),
            ["Landroid/telephony/SmsManager;", "sendTextMessage"],
        )
        finding = next(f for f in result["suspicious_apis"]
                       if f["api"] == "SmsManager.sendTextMessage")
        self.assertEqual("reference", finding["evidence_type"])
        self.assertLess(finding["score"], 15)

    def test_common_library_dex_loader_is_report_only(self):
        dx = _Analysis([_Method("Ldalvik/system/DexClassLoader;", "loadClass")])
        dx.methods[0].get_xref_from = lambda: [
            (None, _Caller("Lcom/google/android/gms/internal/Module;", "load"), None)
        ]
        result = api_patterns.analyze_apis(dx, [])
        finding = next(f for f in result["suspicious_apis"] if f["api"] == "DexClassLoader")
        self.assertEqual(0, finding["score"])
        self.assertTrue(finding["library_context"])

    def test_first_party_dex_loader_remains_high_confidence(self):
        dx = _Analysis([_Method("Ldalvik/system/DexClassLoader;", "loadClass")])
        result = api_patterns.analyze_apis(dx, [])
        finding = next(f for f in result["suspicious_apis"] if f["api"] == "DexClassLoader")
        self.assertEqual(12, finding["score"])
        self.assertFalse(finding["library_context"])


class IocAccuracyTests(unittest.TestCase):
    def test_ordinary_https_links_are_reported_but_not_scored_as_risky(self):
        result = iocs.extract_iocs([
            "https://www.paypal.me/example",
            "https://discord.com/channels/example",
        ])
        self.assertEqual(2, result["counts"]["urls"])
        self.assertEqual([], result["suspicious_urls"])

    def test_risky_url_has_transparent_reasons(self):
        result = iocs.extract_iocs(["http://verify-account.xyz:8080/login/upload"])
        finding = result["suspicious_urls"][0]
        self.assertIn("higher-risk .xyz domain", finding["reasons"])
        self.assertIn("fraud/C2-like path", finding["reasons"])
        self.assertIn("non-standard port 8080", finding["reasons"])
        self.assertIn("cleartext HTTP", finding["reasons"])

    def test_benign_allowlist_requires_dns_label_boundary(self):
        result = iocs.extract_iocs(["http://notgoogle.com/login"])
        self.assertIn("notgoogle.com", result["domains"])
        self.assertEqual(1, result["counts"]["suspicious_urls"])


class YaraAccuracyTests(unittest.TestCase):
    def test_invalid_unicode_from_malformed_dex_does_not_abort_scan(self):
        result = yara_scan.scan(
            ["ordinary text", "malformed\ud800string"],
            [],
            "org.example.robust",
        )
        self.assertNotIn("error", result)

    def test_generic_sms_and_http_library_strings_do_not_trigger_otp_stealer(self):
        result = yara_scan.scan([
            "Landroid/telephony/SmsManager;",
            "Ljava/net/HttpURLConnection;",
            "https://example.org/help",
        ], ["android.permission.INTERNET"], "org.example.calculator")
        self.assertNotIn("SMS_OTP_Stealer", {m["rule"] for m in result["matches"]})

    def test_sms_read_permission_and_outbound_channel_trigger_otp_stealer(self):
        result = yara_scan.scan(
            ["Ljava/net/HttpURLConnection;"],
            ["android.permission.READ_SMS", "android.permission.INTERNET"],
            "org.example.suspicious",
        )
        self.assertIn("SMS_OTP_Stealer", {m["rule"] for m in result["matches"]})

    def test_install_permission_alone_is_not_a_dynamic_dropper(self):
        result = yara_scan.scan(
            ["ordinary file manager"],
            ["android.permission.REQUEST_INSTALL_PACKAGES"],
            "org.example.files",
        )
        self.assertNotIn("Dynamic_Dropper", {m["rule"] for m in result["matches"]})

    def test_install_permission_plus_dex_loader_triggers_dynamic_dropper(self):
        result = yara_scan.scan(
            ["Ldalvik/system/DexClassLoader;"],
            ["android.permission.REQUEST_INSTALL_PACKAGES"],
            "org.example.dropper",
        )
        self.assertIn("Dynamic_Dropper", {m["rule"] for m in result["matches"]})

    def test_password_manager_terms_without_fraud_capability_do_not_match_banking(self):
        result = yara_scan.scan(
            ["card number", "cvv", "otp", "credit card"],
            [],
            "org.example.passwords",
        )
        self.assertNotIn("Banking_Credential_Keywords", {m["rule"] for m in result["matches"]})

    def test_overlay_alone_does_not_turn_credential_terms_into_banking_malware(self):
        result = yara_scan.scan(
            ["card number", "cvv", "otp"],
            ["android.permission.SYSTEM_ALERT_WINDOW"],
            "org.example.video",
        )
        self.assertNotIn("Banking_Credential_Keywords", {m["rule"] for m in result["matches"]})

    def test_sms_capability_correlates_with_credential_terms(self):
        result = yara_scan.scan(
            ["card number", "cvv", "otp"],
            ["android.permission.READ_SMS"],
            "org.example.phish",
        )
        self.assertIn("Banking_Credential_Keywords", {m["rule"] for m in result["matches"]})


class RiskCalibrationTests(unittest.TestCase):
    def test_benign_like_overlay_app_stays_low(self):
        perm = permissions.analyze_permissions([
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET",
        ])
        api = {
            "suspicious_apis": [
                {"api": "Clipboard read", "score": 3, "evidence_type": "invoked"},
                {"api": "PackageManager.setComponentEnabledSetting", "score": 1,
                 "evidence_type": "invoked"},
            ],
            "count": 2,
        }
        risk = risk_scoring.compute_risk(
            perm, api, _empty_iocs(["https://www.paypal.me/example"]),
            {"score": 2, "signals": [{"signal": "minified"}]},
            apkid_result={"score": 3, "findings": [{"name": "Build check"}]},
            cert_result={"score": 0},
            comp_result={"score": 10, "unguarded_count": 3},
        )
        self.assertLessEqual(risk["risk_score"], 20)
        self.assertEqual("Low", risk["severity"])
        self.assertNotIn("Exported components", {b["category"] for b in risk["score_breakdown"]})

    def test_corroborated_fraud_chain_adds_explainable_bonus(self):
        perm = permissions.analyze_permissions([
            "android.permission.READ_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET",
        ])
        risk = risk_scoring.compute_risk(
            perm, {"suspicious_apis": [], "count": 0},
            iocs.extract_iocs(["http://fake-bank.xyz/login"]),
            {"score": 0, "signals": []},
        )
        correlation = next(b for b in risk["score_breakdown"]
                           if b["category"] == "Correlated fraud behaviours")
        self.assertGreaterEqual(correlation["points"], 16)
        self.assertIn("SMS interception + outbound channel", correlation["detail"])

    def test_virustotal_does_not_change_local_score(self):
        analysis = {"risk_score": 0, "severity": "Low", "score_breakdown": []}
        risk_scoring.apply_virustotal(analysis, {
            "queried": True,
            "file": {"found": True, "malicious": 25, "suspicious": 4},
            "flagged_domains": [{"domain": "example.test"}],
        })
        self.assertEqual(0, analysis["risk_score"])
        self.assertEqual("Low", analysis["severity"])
        self.assertEqual([], analysis["score_breakdown"])
        self.assertTrue(analysis["virustotal"]["queried"])

    def test_virustotal_preserves_existing_local_verdict(self):
        analysis = {"risk_score": 48, "severity": "High", "score_breakdown": [
            {"category": "Local evidence", "points": 48, "detail": "test"},
        ]}
        risk_scoring.apply_virustotal(analysis, {
            "queried": True,
            "file": {"found": True, "malicious": 5, "suspicious": 0},
            "flagged_domains": [],
        })
        self.assertEqual(48, analysis["risk_score"])
        self.assertEqual("High", analysis["severity"])
        self.assertEqual(1, len(analysis["score_breakdown"]))

    def test_ml_below_validated_threshold_does_not_inflate_score(self):
        analysis = {"risk_score": 9, "severity": "Low", "score_breakdown": []}
        risk_scoring.apply_ml(analysis, {
            "available": True,
            "malware_probability": 0.58,
            "decision_threshold": 0.75,
            "prediction": "benign",
        })
        self.assertEqual(9, analysis["risk_score"])
        self.assertEqual([], analysis["score_breakdown"])

    def test_headless_obfuscated_loader_chain_is_high_risk(self):
        perm = permissions.analyze_permissions([
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET",
        ])
        api = {
            "suspicious_apis": [{
                "api": "DexClassLoader", "score": 12,
                "evidence_type": "invoked",
            }],
            "count": 1,
        }
        risk = risk_scoring.compute_risk(
            perm,
            api,
            _empty_iocs(),
            {"score": 10, "signals": [{"signal": "Dynamic DEX loading"}]},
            manifest_result={
                "main_activity": "",
                "services": ["org.example.LoaderService"],
                "receivers": ["org.example.BootReceiver"],
            },
        )
        self.assertGreaterEqual(risk["risk_score"], 41)
        correlation = next(
            item for item in risk["score_breakdown"]
            if item["category"] == "Correlated fraud behaviours"
        )
        self.assertIn("background-only entry points", correlation["detail"])


class VerdictPolicyTests(unittest.TestCase):
    def test_critical_heuristics_are_likely_not_confirmed(self):
        analysis = {"valid_apk": True, "risk_score": 90, "severity": "Critical"}
        verdict, _basis = _evidence_assessment(analysis)
        self.assertEqual("Likely Malicious", verdict)
        self.assertEqual("Likely Malicious", _template_report(analysis)["threat_assessment"])

    def test_external_detection_cannot_override_local_verdict(self):
        analysis = {
            "valid_apk": True,
            "risk_score": 90,
            "severity": "Critical",
            "virustotal": {"file": {"found": True, "malicious": 8}},
        }
        verdict, basis = _evidence_assessment(analysis)
        self.assertEqual("Likely Malicious", verdict)
        self.assertIn("locally extracted evidence", basis)

    def test_model_output_is_schema_checked_and_cannot_override_verdict(self):
        analysis = {"valid_apk": True, "risk_score": 80, "severity": "Critical"}
        report = _normalise_report({
            "executive_summary": "Useful summary",
            "technical_summary": 123,
            "threat_assessment": "Confirmed Malicious",
            "key_findings": "not-a-list",
            "attack_chain": ["one", "two"],
            "recommended_actions": None,
        }, analysis)
        self.assertEqual("Likely Malicious", report["threat_assessment"])
        self.assertIsInstance(report["technical_summary"], str)
        self.assertIsInstance(report["key_findings"], list)
        self.assertEqual(["one", "two"], report["attack_chain"])

    def test_low_partial_analysis_is_inconclusive(self):
        analysis = {
            "valid_apk": True,
            "analysis_quality": "partial",
            "risk_score": 7,
            "severity": "Low",
        }
        verdict, basis = _evidence_assessment(analysis)
        self.assertEqual("Inconclusive", verdict)
        self.assertIn("DEX control-flow", basis)


class PartialAnalysisTests(unittest.TestCase):
    def test_raw_dex_string_recovery_is_bounded_and_deduplicated(self):
        class FakeApk:
            def get_files(self):
                return ["classes.dex", "classes2.dex", "assets/data.bin"]

            def get_file(self, name):
                return {
                    "classes.dex": b"\x00Landroid/telephony/SmsManager;\x00sendTextMessage\x00",
                    "classes2.dex": b"\x00sendTextMessage\x00http://c2.example/login\x00",
                }[name]

        strings = static_analyzer._collect_raw_dex_strings(FakeApk())
        self.assertEqual(1, strings.count("sendTextMessage"))
        self.assertIn("Landroid/telephony/SmsManager;", strings)
        self.assertIn("http://c2.example/login", strings)


class RobustnessTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_cleanup_removes_only_stale_owned_uploads(self):
        with tempfile.TemporaryDirectory() as directory:
            owned = os.path.join(directory, f"{main.TEMP_UPLOAD_PREFIX}old.apk")
            recent = os.path.join(directory, f"{main.TEMP_UPLOAD_PREFIX}recent.apk")
            foreign = os.path.join(directory, "someone-else.apk")
            for path in (owned, recent, foreign):
                with open(path, "wb") as stream:
                    stream.write(b"test")
            old_time = time.time() - main.TEMP_UPLOAD_MAX_AGE_SECONDS - 60
            os.utime(owned, (old_time, old_time))
            os.utime(foreign, (old_time, old_time))

            with patch.object(main.tempfile, "gettempdir", return_value=directory):
                main._remove_stale_temporary_uploads()

            self.assertFalse(os.path.exists(owned))
            self.assertTrue(os.path.exists(recent))
            self.assertTrue(os.path.exists(foreign))

    async def test_upload_is_streamed_and_bounded(self):
        original_limit = main.MAX_UPLOAD_MB
        main.MAX_UPLOAD_MB = 1
        try:
            upload = UploadFile(filename="large.apk", file=BytesIO(b"x" * (1024 * 1024 + 1)))
            with self.assertRaises(HTTPException) as ctx:
                await main._spool_upload(upload)
            self.assertEqual(413, ctx.exception.status_code)

            small = UploadFile(filename="small.apk", file=BytesIO(b"PK\x03\x04test"))
            path, size = await main._spool_upload(small)
            try:
                self.assertEqual(8, size)
                self.assertTrue(os.path.exists(path))
            finally:
                os.remove(path)
        finally:
            main.MAX_UPLOAD_MB = original_limit

    async def test_cancelled_upload_removes_partial_temporary_file(self):
        class CancelledUpload:
            def __init__(self):
                self.reads = 0

            async def read(self, _size):
                self.reads += 1
                if self.reads == 1:
                    return b"partial apk bytes"
                raise asyncio.CancelledError

        real_named_temporary_file = tempfile.NamedTemporaryFile
        created_paths = []

        def tracked_temporary_file(*args, **kwargs):
            handle = real_named_temporary_file(*args, **kwargs)
            created_paths.append(handle.name)
            return handle

        with patch.object(
            main.tempfile, "NamedTemporaryFile", side_effect=tracked_temporary_file,
        ):
            with self.assertRaises(asyncio.CancelledError):
                await main._spool_upload(CancelledUpload())

        self.assertEqual(1, len(created_paths))
        self.assertFalse(os.path.exists(created_paths[0]))

    async def test_dynamic_runner_is_dispatched_off_the_event_loop(self):
        upload = UploadFile(filename="sample.apk", file=BytesIO(b"PK\x03\x04test"))
        sandbox_state = {
            "available": True,
            "serial": "emulator-5554",
            "devices": [{"serial": "emulator-5554", "avd_name": "FraudSandbox"}],
        }
        result = {"available": True, "ran": True, "dynamic_score": 0}
        with patch.object(main.dyn_sandbox, "status", return_value=sandbox_state), \
             patch.object(main, "_apk_identity", return_value=("org.test", ".Main")), \
             patch.object(main, "run_in_threadpool", new=AsyncMock(return_value=result)) as dispatch:
            response = await main.dynamic_analyze(
                upload, 15, False, False, None, "tree",
            )

        dispatch.assert_awaited_once()
        args, kwargs = dispatch.await_args
        self.assertIs(main.dyn_sandbox.run_dynamic, args[0])
        self.assertEqual("org.test", args[2])
        self.assertEqual("emulator-5554", kwargs["serial"])
        self.assertEqual(200, response.status_code)

    async def test_linked_dynamic_run_returns_and_persists_final_score(self):
        apk_bytes = b"PK\x03\x04matching-apk"
        upload = UploadFile(filename="sample.apk", file=BytesIO(apk_bytes))
        analysis = {
            "file": {"sha256": hashlib.sha256(apk_bytes).hexdigest()},
            "risk_score": 68,
            "severity": "High",
            "score_breakdown": [],
        }
        sandbox_state = {
            "available": True,
            "serial": "emulator-5554",
            "devices": [{"serial": "emulator-5554", "avd_name": "FraudSandbox"}],
        }
        dynamic_result = {
            "available": True, "ran": True, "duration": 15,
            "dynamic_score": 21, "score_breakdown": [],
        }
        with patch.object(main.dyn_sandbox, "status", return_value=sandbox_state), \
             patch.object(main, "_apk_identity", return_value=("org.test", ".Main")), \
             patch.object(main.dyn_sandbox, "run_dynamic", return_value=dynamic_result), \
             patch.object(main.db, "get_sample", return_value={
                 "analysis": analysis, "report": {"generated_by": "test"},
             }), \
             patch.object(main.db, "update_sample_artifacts", return_value=True) as persist:
            response = await main.dynamic_analyze(
                upload, 15, False, False, None, "tree", "case-123",
            )

        payload = response.body.decode("utf-8")
        self.assertIn('"final_score":89', payload)
        self.assertEqual(68, analysis["risk_score"])
        self.assertEqual(89, analysis["final_score"])
        persist.assert_called_once()

    async def test_linked_dynamic_run_rejects_a_different_apk_before_execution(self):
        upload = UploadFile(filename="other.apk", file=BytesIO(b"different"))
        sandbox_state = {
            "available": True,
            "serial": "emulator-5554",
            "devices": [{"serial": "emulator-5554", "avd_name": "FraudSandbox"}],
        }
        with patch.object(main.dyn_sandbox, "status", return_value=sandbox_state), \
             patch.object(main.db, "get_sample", return_value={
                 "analysis": {"file": {"sha256": "0" * 64}, "risk_score": 30},
                 "report": {},
             }), \
             patch.object(main.dyn_sandbox, "run_dynamic") as runner:
            with self.assertRaises(HTTPException) as context:
                await main.dynamic_analyze(
                    upload, 15, False, False, None, "tree", "case-123",
                )

        self.assertEqual(400, context.exception.status_code)
        runner.assert_not_called()

    async def test_analysis_failure_does_not_disclose_internal_details(self):
        upload = UploadFile(filename="sample.apk", file=BytesIO(b"PK\x03\x04test"))
        with patch.object(main.static_analyzer, "engine_available", return_value=True), \
             patch.object(
                 main.static_analyzer, "analyze",
                 side_effect=RuntimeError(r"secret path F:\private\sample.apk"),
             ):
            with self.assertRaises(HTTPException) as context:
                await main.analyze(upload)

        self.assertEqual(500, context.exception.status_code)
        self.assertEqual(
            "Analysis failed; see server logs for details", context.exception.detail,
        )

    async def test_pdf_escapes_untrusted_markup(self):
        analysis = {
            "file": {"filename": "<b>fake.apk</b>", "sha256": "a", "md5": "b"},
            "manifest": {"package_name": "<script>alert(1)</script>"},
            "risk_score": 0,
            "severity": "Low",
            "score_breakdown": [],
            "final_score": 12,
            "final_severity": "Low",
            "final_score_breakdown": [{
                "category": "Observed runtime behaviour",
                "points": 12,
                "detail": "<b>runtime evidence</b>",
            }],
            "latest_dynamic": {"duration": 15, "dynamic_score": 12},
            "iocs": {"urls": ["http://x.test/<b>bad</b>"]},
            "agentic": {
                "status": "completed", "provider": "test", "model": "fake",
                "steps_used": 2,
                "hypotheses": [{
                    "claim": "<script>untrusted claim</script>", "confidence": "low",
                    "evidence_ids": ["ioc:test"],
                }],
                "gaps": ["review <unknown>"],
                "audit": [{"step": 1, "action": "inspect_network", "status": "ok"}],
            },
        }
        report = {
            "executive_summary": "<b>untrusted summary",
            "technical_summary": "x & y",
            "recommended_actions": ["review <sample>"],
            "generated_by": "test",
        }
        pdf = report_pdf.build_pdf(analysis, report)
        self.assertTrue(pdf.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
