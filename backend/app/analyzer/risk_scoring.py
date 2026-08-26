"""Transparent rule-based risk scoring.

Combines the per-category feature scores into a single 0–100 risk score with a
fully itemised breakdown so the report can explain every point. Mirrors plan.md
section 7. Each sub-category is capped to avoid one feature dominating.
"""

CATEGORY_CAPS = {
    "permissions": 40,
    "apis": 25,
    "network": 15,
    "obfuscation": 18,
    "keywords": 12,
    "yara": 40,
    "correlation": 20,
}

SEVERITY_BANDS = [
    (0, 20, "Low"),
    (21, 40, "Medium"),
    (41, 70, "High"),
    (71, 100, "Critical"),
]


def severity_for(score: int) -> str:
    for lo, hi, label in SEVERITY_BANDS:
        if lo <= score <= hi:
            return label
    return "Critical" if score > 100 else "Low"


def compute_risk(perm_result, api_result, ioc_result, obf_result, yara_result=None,
                 apkid_result=None, cert_result=None, comp_result=None,
                 manifest_result=None):
    breakdown = []

    # --- Permissions ---
    # Broad legitimate apps often request many sensitive permissions. Apply diminishing
    # returns: preserve the strongest capability, half of the second, and one quarter
    # of the remainder. Correlated fraud chains below restore confidence when those
    # capabilities form a discriminative combination.
    perm_weights = sorted(
        (max(0, f.get("score", 0)) for f in perm_result.get("dangerous", [])),
        reverse=True,
    )
    perm_score = 0
    if perm_weights:
        perm_score = perm_weights[0]
        if len(perm_weights) > 1:
            perm_score += round(perm_weights[1] * 0.5)
        if len(perm_weights) > 2:
            perm_score += round(sum(perm_weights[2:]) * 0.25)
    perm_score = min(perm_score, CATEGORY_CAPS["permissions"])
    if perm_score:
        breakdown.append({
            "category": "Dangerous permissions",
            "points": perm_score,
            "detail": f"{perm_result.get('dangerous_count', 0)} dangerous permission(s)",
        })

    # --- Suspicious APIs ---
    api_findings = api_result.get("suspicious_apis", [])
    scored_apis = [f for f in api_findings if f.get("score", 0) > 0]
    api_score = sum(f["score"] for f in scored_apis)
    api_score = min(api_score, CATEGORY_CAPS["apis"])
    if api_score:
        breakdown.append({
            "category": "Suspicious APIs",
            "points": api_score,
            "detail": (f"{len(scored_apis)} risk-relevant API(s)"
                       + (f"; {len(api_findings) - len(scored_apis)} report-only"
                          if len(api_findings) > len(scored_apis) else "")),
        })

    # --- Network / IOC ---
    counts = ioc_result.get("counts", {})
    net_score = 0
    net_bits = []
    suspicious_urls = ioc_result.get("suspicious_urls", []) or []
    scoreable_urls = [u for u in suspicious_urls if u.get("confidence") in ("medium", "high")]
    if scoreable_urls:
        net_score += min(sum(u.get("score", 0) for u in scoreable_urls), 10)
        net_bits.append(f"{len(scoreable_urls)} higher-confidence URL(s)")
    if counts.get("telegram_tokens"):
        net_score += 10; net_bits.append("Telegram bot token")
    if counts.get("secrets"):
        net_score += 4; net_bits.append("hardcoded secret(s)")
    net_score = min(net_score, CATEGORY_CAPS["network"])
    if net_score:
        breakdown.append({
            "category": "Network indicators",
            "points": net_score,
            "detail": ", ".join(net_bits),
        })

    # --- Obfuscation ---
    obf_score = min(obf_result.get("score", 0), CATEGORY_CAPS["obfuscation"])
    if obf_score:
        breakdown.append({
            "category": "Obfuscation",
            "points": obf_score,
            "detail": f"{len(obf_result.get('signals', []))} signal(s)",
        })

    # --- Suspicious keywords (score only high-signal financial terms; generic words
    #     like "login"/"password" appear in nearly every app and are not scored) ---
    # Credential words are expected in password managers, authenticators, payment
    # libraries, and UI translations. They remain visible IOC context and only score
    # through correlated fraud rules below or a capability-qualified YARA match.

    # --- YARA signatures ---
    if yara_result and yara_result.get("matches"):
        y_score = min(yara_result.get("score", 0), CATEGORY_CAPS["yara"])
        if y_score:
            breakdown.append({
                "category": "YARA signatures",
                "points": y_score,
                "detail": ", ".join(m["rule"] for m in yara_result["matches"][:5]),
            })

    # --- APKiD packer / anti-analysis ---
    if apkid_result and apkid_result.get("findings"):
        a_score = min(apkid_result.get("score", 0), 30)
        if a_score:
            scored_findings = [f for f in apkid_result["findings"] if f.get("score", 0) > 0]
            breakdown.append({
                "category": "Packer / anti-analysis (APKiD)",
                "points": a_score,
                "detail": ", ".join(f["name"] for f in scored_findings[:4]),
            })

    # --- Certificate red-flags ---
    if cert_result and cert_result.get("score"):
        breakdown.append({
            "category": "Certificate red-flags",
            "points": min(cert_result["score"], 12),
            "detail": ", ".join(f["flag"] for f in cert_result.get("flags", [])),
        })

    # Exported components are a vulnerability/attack-surface finding, not evidence that
    # the APK itself is malicious. They remain in the report but do not raise malware risk.

    # --- Correlated fraud chains ---
    # Combinations are more discriminative than isolated permissions or library calls.
    perms = {p.get("name") for p in perm_result.get("dangerous", [])}
    all_perms = {p.rsplit(".", 1)[-1] for p in perm_result.get("all_permissions", [])}
    apis = {a.get("api") for a in api_result.get("suspicious_apis", [])}
    invoked_apis = {
        a.get("api") for a in api_result.get("suspicious_apis", [])
        if a.get("evidence_type", "invoked") == "invoked"
    }
    has_network = bool(
        "INTERNET" in all_perms
        or counts.get("urls")
        or invoked_apis & {"HttpURLConnection", "OkHttp", "Raw Socket"}
    )
    correlation_score = 0
    correlation_bits = []
    if perms & {"READ_SMS", "RECEIVE_SMS"} and has_network:
        correlation_score += 8
        correlation_bits.append("SMS interception + outbound channel")
    if "BIND_ACCESSIBILITY_SERVICE" in perms and "SYSTEM_ALERT_WINDOW" in perms:
        correlation_score += 8
        correlation_bits.append("accessibility automation + overlay")
    if "REQUEST_INSTALL_PACKAGES" in perms and apis & {"DexClassLoader", "PathClassLoader"}:
        correlation_score += 8
        correlation_bits.append("package installation + runtime code loading")
    if ioc_result.get("financial_keywords") and (
            perms & {"SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "READ_SMS", "RECEIVE_SMS"}):
        correlation_score += 6
        correlation_bits.append("financial targeting + credential/OTP capability")
    has_suspicious_network = bool(
        scoreable_urls or counts.get("telegram_tokens") or counts.get("secrets")
    )
    if "NotificationListenerService" in apis and has_suspicious_network:
        correlation_score += 5
        correlation_bits.append("notification access + suspicious outbound indicator")
    yara_rules = {m.get("rule") for m in (yara_result or {}).get("matches", [])}
    apkid_categories = {f.get("category") for f in (apkid_result or {}).get("findings", [])}
    if "DexClassLoader" in invoked_apis and (
            "Dynamic_Dropper" in yara_rules
            or apkid_categories & {"Packer", "Protector", "Dropper"}):
        correlation_score += 10
        correlation_bits.append("invoked runtime loading + dropper/packer signature")
    if "DexClassLoader" in invoked_apis and obf_result.get("score", 0) >= 8:
        correlation_score += 8
        correlation_bits.append("invoked runtime loading + obfuscated payload path")
        manifest_result = manifest_result or {}
        has_background_entry = bool(
            manifest_result.get("services") or manifest_result.get("receivers")
        )
        if ("RECEIVE_BOOT_COMPLETED" in perms and has_background_entry
                and not manifest_result.get("main_activity")):
            correlation_score += 8
            correlation_bits.append("boot persistence + background-only entry points")
    correlation_score = min(correlation_score, CATEGORY_CAPS["correlation"])
    if correlation_score:
        breakdown.append({
            "category": "Correlated fraud behaviours",
            "points": correlation_score,
            "detail": "; ".join(correlation_bits),
        })

    total = min(sum(b["points"] for b in breakdown), 100)
    severity = severity_for(total)

    return {
        "risk_score": total,
        "severity": severity,
        "score_breakdown": breakdown,
    }


def apply_ml(analysis: dict, ml: dict) -> dict:
    """Fold the ML classifier's malware probability into the score (plan §7 hybrid:
    rules + ML). Adds a breakdown entry and recomputes total/severity. No-op if the
    model isn't available. Mutates and returns `analysis`."""
    analysis["ml"] = ml
    if not ml or not ml.get("available") or ml.get("error") is not None:
        return analysis
    prob = ml.get("malware_probability", 0.0)
    threshold = ml.get("decision_threshold", 0.8)
    if prob >= threshold and ml.get("prediction") in ("flagged", "malware"):
        points = min(round(prob * 20), 20)
        if points:
            analysis.setdefault("score_breakdown", []).append({
                "category": "ML classifier",
                "points": points,
                "detail": f"malware probability {prob:.0%} (threshold {threshold:.0%})",
            })
            total = min(sum(b["points"] for b in analysis["score_breakdown"]), 100)
            analysis["risk_score"] = total
            analysis["severity"] = severity_for(total)
    return analysis


def apply_virustotal(analysis: dict, vt: dict) -> dict:
    """Attach optional VirusTotal context without changing the local verdict.

    The platform's score and severity are intentionally derived only from its own
    static, ML, and sandbox evidence.  VirusTotal is displayed as external
    corroboration and must never become a hidden scoring dependency.
    """
    analysis["virustotal"] = vt
    return analysis


def derive_behaviors(perm_result, api_result, ioc_result, obf_result):
    """Heuristic behaviour labels for the summary/IOC section."""
    behaviors = set()
    perms = {p["name"] for p in perm_result.get("dangerous", [])}
    apis = {a["api"] for a in api_result.get("suspicious_apis", [])}

    if perms & {"READ_SMS", "RECEIVE_SMS"} or "SmsManager.sendTextMessage" in apis:
        behaviors.add("OTP / SMS theft")
    if "BIND_ACCESSIBILITY_SERVICE" in perms or "AccessibilityService" in apis:
        behaviors.add("Accessibility abuse (screen scraping / auto-click)")
    if "SYSTEM_ALERT_WINDOW" in perms:
        if "BIND_ACCESSIBILITY_SERVICE" in perms or ioc_result.get("financial_keywords"):
            behaviors.add("Potential overlay attack (fake login screen)")
        else:
            behaviors.add("Overlay capability")
    if "NotificationListenerService" in apis:
        behaviors.add("Notification / alert stealing")
    if "DexClassLoader" in apis or (
            "REQUEST_INSTALL_PACKAGES" in perms and "PathClassLoader" in apis):
        behaviors.add("Dropper / dynamic payload loading")
    elif "REQUEST_INSTALL_PACKAGES" in perms:
        behaviors.add("APK installation capability")
    network_api = apis & {"HttpURLConnection", "OkHttp", "Raw Socket"}
    sensitive_access = perms & {
        "READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "READ_CALL_LOG",
        "BIND_ACCESSIBILITY_SERVICE",
    }
    if ioc_result.get("suspicious_urls") and sensitive_access:
        behaviors.add("Potential command-and-control / data-exfiltration path")
    elif ioc_result.get("counts", {}).get("urls") or network_api:
        behaviors.add("Network communication capability / embedded endpoints")
    if ioc_result.get("counts", {}).get("telegram_tokens"):
        behaviors.add("Telegram-based C2 / exfiltration")
    if "READ_CONTACTS" in perms:
        behaviors.add("Contact harvesting / victim spreading")
    if obf_result.get("is_obfuscated"):
        behaviors.add("Code obfuscation / evasion")
    if "BIND_DEVICE_ADMIN" in perms or "DevicePolicyManager abuse" in apis:
        behaviors.add("Device-admin abuse (anti-removal)")

    return sorted(behaviors)


def recommendations(severity, behaviors, ioc_result):
    recs = []
    if severity in ("High", "Critical"):
        recs += [
            "Block the APK SHA256 hash across endpoints",
            "Blacklist the contacted domains/IPs at the network gateway",
            "Notify the bank fraud-monitoring / SOC team",
        ]
    if "OTP / SMS theft" in behaviors:
        recs.append("Alert potentially affected customers; review recent OTP-based transactions")
    if ioc_result.get("counts", {}).get("telegram_tokens"):
        recs.append("Report the Telegram bot token to the platform for takedown")
    recs.append("Submit the sample to a malware-intelligence platform (e.g. VirusTotal)")
    if severity in ("Low", "Medium"):
        recs.append("Monitor; escalate if combined with other fraud signals")
    # de-dup, preserve order
    seen, out = set(), []
    for r in recs:
        if r not in seen:
            seen.add(r); out.append(r)
    return out
