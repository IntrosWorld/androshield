"""Harmless live smoke test for the configured agent provider.

Uses synthetic extracted findings only. No APK is opened, installed, or executed.
Run from backend: ``python tools/smoke_agent.py``.
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.agent.orchestrator import agent_health, run_investigation


SYNTHETIC_FINDINGS = {
    "valid_apk": True,
    "analysis_quality": "full",
    "risk_score": 56,
    "severity": "High",
    "manifest": {
        "package_name": "org.example.syntheticbank",
        "app_name": "Synthetic Test Bank",
        "services": [],
        "receivers": [],
    },
    "permissions": {"dangerous": [
        {"name": "android.permission.READ_SMS", "score": 12,
         "reason": "Can read SMS and OTP messages"},
        {"name": "android.permission.INTERNET", "score": 0,
         "reason": "Can communicate over the network"},
    ]},
    "apis": {"suspicious_apis": [{
        "api": "SmsManager.sendTextMessage", "score": 8,
        "behaviour": "Can send SMS", "evidence_type": "invoked",
    }]},
    "iocs": {
        "urls": ["http://synthetic-test.invalid/login"],
        "domains": ["synthetic-test.invalid"], "ips": [],
        "suspicious_keywords": [{"keyword": "otp"}],
    },
    "yara": {"matches": []},
    "apkid": {"findings": []},
    "mitre": {"techniques": []},
    "certificate": {"flags": []},
    "components": {"count": 0, "unguarded_count": 0, "exported": []},
    "score_breakdown": [
        {"category": "Dangerous permissions", "points": 12,
         "detail": "READ_SMS permits OTP access"},
        {"category": "Suspicious APIs", "points": 8,
         "detail": "Invoked SMS sending API"},
    ],
    "detected_behaviors": ["SMS access", "Outbound communication"],
}


def main() -> int:
    health = agent_health(check_provider=True)
    print(json.dumps({"health": health}, indent=2))
    provider_health = health.get("provider_health", {})
    if not provider_health.get("available"):
        print("Configured provider is unavailable.", file=sys.stderr)
        return 2
    before = json.dumps(SYNTHETIC_FINDINGS, sort_keys=True)
    result = run_investigation(
        SYNTHETIC_FINDINGS,
        max_steps=6,
        time_budget_seconds=300,
    )
    print(json.dumps({"investigation": result}, indent=2))
    if json.dumps(SYNTHETIC_FINDINGS, sort_keys=True) != before:
        print("FAIL: input findings changed", file=sys.stderr)
        return 3
    if result.get("status") != "completed":
        print("FAIL: investigation did not complete", file=sys.stderr)
        return 4
    if not result.get("audit") or not result.get("hypotheses"):
        print("FAIL: expected audited actions and grounded hypotheses", file=sys.stderr)
        return 5
    print("PASS: bounded investigation completed without changing deterministic findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
