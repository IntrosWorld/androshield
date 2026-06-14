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
                 apkid_result=None, cert_result=None, comp_result=None):
    breakdown = []

    # --- Permissions ---
    perm_score = sum(f["score"] for f in perm_result.get("dangerous", []))
    perm_score = min(perm_score, CATEGORY_CAPS["permissions"])
    if perm_score:
        breakdown.append({
            "category": "Dangerous permissions",
            "points": perm_score,
            "detail": f"{perm_result.get('dangerous_count', 0)} dangerous permission(s)",
        })

    # --- Suspicious APIs ---
    api_score = sum(f["score"] for f in api_result.get("suspicious_apis", []))
    api_score = min(api_score, CATEGORY_CAPS["apis"])
    if api_score:
        breakdown.append({
            "category": "Suspicious APIs",
            "points": api_score,
            "detail": f"{api_result.get('count', 0)} suspicious API(s)",
        })

    # --- Network / IOC ---
    counts = ioc_result.get("counts", {})
    net_score = 0
    net_bits = []
    if counts.get("urls"):
        net_score += min(counts["urls"], 5); net_bits.append(f"{counts['urls']} URL(s)")
    if counts.get("ips"):
        net_score += min(counts["ips"] * 3, 8); net_bits.append(f"{counts['ips']} IP(s)")
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
    fin_kw = ioc_result.get("financial_keywords", [])
    kw_score = min(len(fin_kw) * 3, CATEGORY_CAPS["keywords"])
    if kw_score:
        breakdown.append({
            "category": "Banking/fraud keywords",
            "points": kw_score,
            "detail": ", ".join(fin_kw[:8]),
        })

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
            breakdown.append({
                "category": "Packer / anti-analysis (APKiD)",
                "points": a_score,
                "detail": ", ".join(f["name"] for f in apkid_result["findings"][:4]),
            })

    # --- Certificate red-flags ---
    if cert_result and cert_result.get("score"):
        breakdown.append({
            "category": "Certificate red-flags",
            "points": min(cert_result["score"], 12),
            "detail": ", ".join(f["flag"] for f in cert_result.get("flags", [])),
        })

    # --- Exported components (attack surface) ---
    if comp_result and comp_result.get("score"):
        breakdown.append({
            "category": "Exported components",
            "points": min(comp_result["score"], 10),
            "detail": f"{comp_result.get('unguarded_count', 0)} unguarded exported component(s)",
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
    if prob >= 0.5:
        points = min(round(prob * 20), 20)
        if points:
            analysis.setdefault("score_breakdown", []).append({
                "category": "ML classifier",
                "points": points,
                "detail": f"malware probability {prob:.0%}",
            })
            total = min(sum(b["points"] for b in analysis["score_breakdown"]), 100)
            analysis["risk_score"] = total
            analysis["severity"] = severity_for(total)
    return analysis


def apply_virustotal(analysis: dict, vt: dict) -> dict:
    """Fold a VirusTotal result into an existing analysis: add a score-breakdown
    entry, recompute the total/severity, and apply a severity floor when multiple
    engines flag the sample. Mutates and returns `analysis`."""
    analysis["virustotal"] = vt
    if not vt or not vt.get("queried"):
        return analysis

    file_res = vt.get("file", {}) or {}
    malicious = file_res.get("malicious", 0) if file_res.get("found") else 0
    suspicious = file_res.get("suspicious", 0) if file_res.get("found") else 0
    flagged_domains = len(vt.get("flagged_domains", []) or [])

    points = 0
    bits = []
    if malicious:
        points += min(malicious * 4, 40)
        bits.append(f"{malicious} engine(s) malicious")
    if suspicious:
        points += min(suspicious * 2, 10)
        bits.append(f"{suspicious} suspicious")
    if flagged_domains:
        points += min(flagged_domains * 5, 15)
        bits.append(f"{flagged_domains} flagged domain(s)")

    if points:
        analysis.setdefault("score_breakdown", []).append({
            "category": "VirusTotal detections",
            "points": points,
            "detail": ", ".join(bits) + (f" — {file_res.get('threat_label')}"
                                         if file_res.get("threat_label") else ""),
        })
        total = min(sum(b["points"] for b in analysis["score_breakdown"]), 100)
        analysis["risk_score"] = total
        sev = severity_for(total)
        # Floor: real multi-engine detection should never read below High/Critical.
        if malicious >= 5 and sev != "Critical":
            sev = "Critical"
        elif malicious >= 1 and sev in ("Low", "Medium"):
            sev = "High"
        analysis["severity"] = sev

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
        behaviors.add("Overlay attack (fake login screen)")
    if "NotificationListenerService" in apis:
        behaviors.add("Notification / alert stealing")
    if "REQUEST_INSTALL_PACKAGES" in perms or "DexClassLoader" in apis:
        behaviors.add("Dropper / dynamic payload loading")
    if ioc_result.get("counts", {}).get("urls") or "HttpURLConnection" in apis or "OkHttp" in apis:
        behaviors.add("Remote server communication / data exfiltration")
    if ioc_result.get("counts", {}).get("telegram_tokens"):
        behaviors.add("Telegram-based C2 / exfiltration")
    if "READ_CONTACTS" in perms:
        behaviors.add("Contact harvesting / victim spreading")
    if obf_result.get("is_obfuscated"):
        behaviors.add("Code obfuscation / evasion")
    if "BIND_DEVICE_ADMIN" in perms or "DevicePolicyManager" in apis:
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
