"""MITRE ATT&CK (Mobile) mapping — fully offline, zero dependencies.

Maps the concrete signals the analyzer already extracts (dangerous permissions,
suspicious API labels, derived behaviours) to ATT&CK Mobile technique IDs so the
report speaks the language SOC/fraud teams use. Reference: https://attack.mitre.org/matrices/mobile/
"""

# technique_id -> (name, tactic)
_TECHNIQUES = {
    "T1417.001": ("Input Capture: Keylogging", "Collection/Credential Access"),
    "T1417.002": ("Input Capture: GUI Input Capture", "Collection/Credential Access"),
    "T1582": ("SMS Control", "Impact/Collection"),
    "T1636.003": ("Protected User Data: Contact List", "Collection"),
    "T1636.004": ("Protected User Data: SMS Messages", "Collection"),
    "T1517": ("Access Notifications", "Collection"),
    "T1513": ("Screen Capture", "Collection"),
    "T1429": ("Audio Capture", "Collection"),
    "T1512": ("Video Capture", "Collection"),
    "T1430": ("Location Tracking", "Collection/Discovery"),
    "T1407": ("Download New Code at Runtime", "Defense Evasion"),
    "T1406": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1655": ("Masquerading", "Defense Evasion"),
    "T1418": ("Software Discovery", "Discovery"),
    "T1426": ("System Information Discovery", "Discovery"),
    "T1437": ("Application Layer Protocol", "Command and Control"),
    "T1521": ("Encrypted Channel", "Command and Control"),
    "T1646": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1623": ("Command and Scripting Interpreter", "Execution"),
    "T1626.001": ("Abuse Elevation Control: Device Administrator", "Privilege Escalation"),
    "T1516": ("Input Injection", "Impact"),
    "T1398": ("Boot or Logon Initialization Scripts", "Persistence/Defense Evasion"),
    "T1660": ("Phishing", "Initial Access"),
    "T1645": ("Compromise Application Executable", "Persistence"),
}

# Rules: (technique_id, source, match-value). source in {"perm","api","behavior"}.
_RULES = [
    # SMS / OTP
    ("T1582", "perm", "READ_SMS"),
    ("T1582", "perm", "RECEIVE_SMS"),
    ("T1582", "perm", "SEND_SMS"),
    ("T1636.004", "perm", "READ_SMS"),
    ("T1582", "api", "SmsManager.sendTextMessage"),
    # Accessibility / overlay / input
    ("T1417.002", "perm", "BIND_ACCESSIBILITY_SERVICE"),
    ("T1417.002", "api", "AccessibilityService"),
    ("T1516", "api", "AccessibilityService"),
    ("T1513", "api", "AccessibilityService"),
    ("T1660", "perm", "SYSTEM_ALERT_WINDOW"),
    ("T1417.001", "perm", "BIND_ACCESSIBILITY_SERVICE"),
    # Notifications
    ("T1517", "api", "NotificationListenerService"),
    # Contacts
    ("T1636.003", "perm", "READ_CONTACTS"),
    # Surveillance
    ("T1429", "perm", "RECORD_AUDIO"),
    ("T1512", "perm", "CAMERA"),
    ("T1430", "perm", "ACCESS_FINE_LOCATION"),
    ("T1430", "perm", "ACCESS_BACKGROUND_LOCATION"),
    # Discovery
    ("T1418", "perm", "QUERY_ALL_PACKAGES"),
    ("T1426", "perm", "READ_PHONE_STATE"),
    ("T1426", "api", "Telephony identifiers"),
    # Runtime code / execution
    ("T1407", "api", "DexClassLoader"),
    ("T1623", "api", "Runtime.exec"),
    ("T1623", "api", "ProcessBuilder"),
    # Network / C2 / exfil
    ("T1437", "api", "HttpURLConnection"),
    ("T1437", "api", "OkHttp"),
    ("T1437", "api", "Raw Socket"),
    ("T1521", "api", "Cipher operation"),
    ("T1646", "behavior", "Potential command-and-control / data-exfiltration path"),
    ("T1646", "behavior", "Telegram-based C2 / exfiltration"),
    # Device admin / persistence
    ("T1626.001", "perm", "BIND_DEVICE_ADMIN"),
    ("T1626.001", "api", "DevicePolicyManager abuse"),
    ("T1398", "perm", "RECEIVE_BOOT_COMPLETED"),
    # Obfuscation / masquerading
    ("T1655", "behavior", "Code obfuscation / evasion"),
]


def map_attack(perm_result, api_result, behaviors, obf_result):
    perms = {p["name"] for p in (perm_result or {}).get("dangerous", [])}
    apis = {a["api"] for a in (api_result or {}).get("suspicious_apis", [])}
    behs = set(behaviors or [])

    # technique_id -> set(evidence)
    matched = {}
    for tid, source, value in _RULES:
        hit = (source == "perm" and value in perms) \
            or (source == "api" and value in apis) \
            or (source == "behavior" and value in behs)
        if hit:
            matched.setdefault(tid, set()).add(value)

    if (obf_result or {}).get("is_obfuscated"):
        matched.setdefault("T1406", set()).add("obfuscation signals")

    techniques = []
    for tid, evidence in matched.items():
        name, tactic = _TECHNIQUES.get(tid, (tid, ""))
        techniques.append({
            "id": tid,
            "name": name,
            "tactic": tactic,
            "evidence": sorted(evidence),
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })
    techniques.sort(key=lambda t: t["id"])
    tactics = sorted({t["tactic"] for t in techniques if t["tactic"]})
    return {"techniques": techniques, "tactics": tactics, "count": len(techniques)}
