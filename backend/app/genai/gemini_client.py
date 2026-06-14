"""Gemini-based threat-reasoning / report generation.

Takes the *extracted findings* (never the raw APK) and asks Gemini to produce an
executive summary, technical narrative and recommendations. If no GEMINI_API_KEY is
configured, falls back to a deterministic template so the platform always returns a
report.
"""
import json
import logging
import os

log = logging.getLogger("gemini")

SYSTEM_PROMPT = """You are a senior mobile-malware analyst supporting a bank's fraud
and SOC teams. You are given STRUCTURED FINDINGS extracted from static analysis of an
Android APK (permissions, suspicious APIs, network indicators, obfuscation signals and
a rule-based risk score). Reason like a malware analyst.

Return ONLY valid minified JSON (no markdown fences) with exactly these keys:
{
  "executive_summary": "2-4 sentence plain-English verdict for a non-technical fraud manager",
  "technical_summary": "1-2 paragraph technical explanation correlating the evidence into attack behaviour",
  "threat_assessment": "one of: Benign, Suspicious, Likely Malicious, Confirmed Malicious",
  "key_findings": ["short bullet", "..."],
  "attack_chain": ["ordered step the malware likely performs", "..."],
  "recommended_actions": ["actionable step for the fraud/SOC team", "..."]
}
Be specific and evidence-driven. Do not invent indicators that are not in the findings."""


def _findings_payload(analysis: dict) -> dict:
    """Trim the full analysis to the evidence the LLM needs."""
    return {
        "package_name": analysis.get("manifest", {}).get("package_name"),
        "app_name": analysis.get("manifest", {}).get("app_name"),
        "sha256": analysis.get("file", {}).get("sha256"),
        "risk_score": analysis.get("risk_score"),
        "severity": analysis.get("severity"),
        "score_breakdown": analysis.get("score_breakdown"),
        "dangerous_permissions": [
            {"name": p["name"], "reason": p["reason"]}
            for p in analysis.get("permissions", {}).get("dangerous", [])
        ],
        "suspicious_apis": [
            {"api": a["api"], "behaviour": a["behaviour"]}
            for a in analysis.get("apis", {}).get("suspicious_apis", [])
        ],
        "network_indicators": {
            "domains": analysis.get("iocs", {}).get("domains", [])[:30],
            "ips": analysis.get("iocs", {}).get("ips", [])[:30],
            "urls": analysis.get("iocs", {}).get("urls", [])[:30],
            "telegram_tokens": bool(analysis.get("iocs", {}).get("telegram_tokens")),
        },
        "obfuscation_signals": [s["signal"] for s in analysis.get("obfuscation", {}).get("signals", [])],
        "certificate_flags": [f["flag"] for f in analysis.get("certificate", {}).get("flags", [])],
        "exported_components": analysis.get("components", {}).get("unguarded_count", 0),
        "decoded_blobs": analysis.get("iocs", {}).get("decoded_blobs", 0),
        "suspicious_keywords": [
            k["keyword"] for k in analysis.get("iocs", {}).get("suspicious_keywords", [])
        ][:20],
        "heuristic_behaviors": analysis.get("detected_behaviors", []),
        "yara_matches": [
            {"rule": m["rule"], "description": m["description"]}
            for m in analysis.get("yara", {}).get("matches", [])
        ],
        "mitre_attack": [
            {"id": t["id"], "name": t["name"]}
            for t in analysis.get("mitre", {}).get("techniques", [])
        ],
        "apkid": [f["name"] for f in analysis.get("apkid", {}).get("findings", [])],
        "ml_verdict": (
            {"prediction": analysis["ml"].get("prediction"),
             "malware_probability": analysis["ml"].get("malware_probability")}
            if analysis.get("ml", {}).get("available") and "malware_probability" in analysis.get("ml", {})
            else None
        ),
        "virustotal": _vt_summary(analysis.get("virustotal")),
    }


def _vt_summary(vt):
    """Compact VirusTotal summary for the LLM (or None if not queried)."""
    if not vt or not vt.get("queried"):
        return None
    f = vt.get("file", {}) or {}
    if not f.get("found"):
        return {"file_seen": False, "note": f.get("note") or f.get("error")}
    return {
        "file_seen": True,
        "malicious_engines": f.get("malicious", 0),
        "suspicious_engines": f.get("suspicious", 0),
        "total_engines": f.get("total_engines", 0),
        "threat_label": f.get("threat_label", ""),
        "sample_detections": [h["result"] for h in f.get("engine_hits", [])][:8],
        "flagged_domains": [d["domain"] for d in vt.get("flagged_domains", [])],
    }


def _template_report(analysis: dict) -> dict:
    """Deterministic fallback when Gemini is unavailable."""
    sev = analysis.get("severity", "Low")
    score = analysis.get("risk_score", 0)
    behaviors = analysis.get("detected_behaviors", [])
    pkg = analysis.get("manifest", {}).get("package_name") or "the application"
    perms = [p["name"] for p in analysis.get("permissions", {}).get("dangerous", [])]
    apis = [a["api"] for a in analysis.get("apis", {}).get("suspicious_apis", [])]

    assessment = {
        "Low": "Benign", "Medium": "Suspicious",
        "High": "Likely Malicious", "Critical": "Confirmed Malicious",
    }.get(sev, "Suspicious")

    exec_summary = (
        f"{pkg} scored {score}/100 ({sev}). "
        + ("It exhibits " + ", ".join(behaviors[:4]) + ". " if behaviors else "")
        + ("Manual review is recommended before clearing this sample."
           if sev in ("High", "Critical") else
           "No strong malicious indicators were found in static analysis.")
    )
    tech = (
        "Static analysis flagged "
        f"{len(perms)} dangerous permission(s) ({', '.join(perms[:6])}) and "
        f"{len(apis)} suspicious API usage(s) ({', '.join(apis[:6])}). "
        + ("Network indicators and obfuscation increase confidence in malicious intent."
           if analysis.get("iocs", {}).get("counts", {}).get("urls") else
           "Limited network indicators were observed in static strings.")
    )
    return {
        "executive_summary": exec_summary,
        "technical_summary": tech,
        "threat_assessment": assessment,
        "key_findings": ([f"Dangerous permissions: {', '.join(perms[:8])}"] if perms else [])
                        + ([f"Suspicious APIs: {', '.join(apis[:8])}"] if apis else [])
                        + ([f"Behaviours: {', '.join(behaviors)}"] if behaviors else []),
        "attack_chain": behaviors,
        "recommended_actions": analysis.get("recommendations", []),
        "generated_by": "template-fallback",
    }


def generate_report(analysis: dict) -> dict:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        log.info("No GEMINI_API_KEY set — using template fallback report.")
        return _template_report(analysis)

    model_name = os.getenv("GEMINI_MODEL", "gemini-2.0-flash").strip()
    payload = _findings_payload(analysis)

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(
            model_name,
            system_instruction=SYSTEM_PROMPT,
            generation_config={"response_mime_type": "application/json", "temperature": 0.2},
        )
        prompt = "STRUCTURED FINDINGS:\n" + json.dumps(payload, indent=2)
        resp = model.generate_content(prompt)
        text = (resp.text or "").strip()
        # Strip accidental code fences.
        if text.startswith("```"):
            text = text.strip("`")
            text = text[text.find("{"):text.rfind("}") + 1]
        report = json.loads(text)
        report["generated_by"] = model_name
        return report
    except Exception as e:
        log.exception("Gemini generation failed; falling back to template.")
        report = _template_report(analysis)
        report["gemini_error"] = str(e)
        return report
