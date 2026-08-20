"""Dangerous-permission catalog and scoring.

Each entry maps a (short) permission name to a weight and the fraud-relevant
reason it matters. Weights mirror the rule table in plan.md section 7. Matching is
done on the *suffix* of the full permission string so both AOSP
("android.permission.READ_SMS") and vendor-prefixed permissions are caught.
"""

# name -> (score, category, why-it-matters)
DANGEROUS_PERMISSIONS = {
    # SMS / OTP theft
    "READ_SMS": (15, "SMS", "Can read SMS — classic OTP/2FA theft"),
    "RECEIVE_SMS": (15, "SMS", "Intercepts incoming SMS — OTP theft"),
    "SEND_SMS": (12, "SMS", "Can send SMS — premium fraud / victim spreading"),
    "RECEIVE_MMS": (8, "SMS", "Intercepts MMS messages"),
    "WRITE_SMS": (8, "SMS", "Can modify the SMS store"),

    # Accessibility / overlay — banking-trojan hallmarks
    "BIND_ACCESSIBILITY_SERVICE": (20, "Accessibility",
                                   "Accessibility service — screen reading / auto-click fraud"),
    # Overlay is legitimate for chat heads, accessibility tools, screen filters, and
    # floating calculators. It becomes high-risk through correlation with accessibility
    # automation or financial targeting in risk_scoring.py.
    "SYSTEM_ALERT_WINDOW": (4, "Overlay",
                            "Draw-over-other-apps — fake login overlay attacks"),

    # Contacts — victim spreading / phishing
    "READ_CONTACTS": (10, "Contacts", "Reads contacts — phishing / spreading"),
    "WRITE_CONTACTS": (6, "Contacts", "Modifies contacts"),
    "GET_ACCOUNTS": (3, "Contacts", "Enumerates device accounts"),

    # Telephony / identity
    # Telephony identifiers were historically ubiquitous in advertising/analytics SDKs.
    # Keep them visible but weak unless combined with fraud-specific capabilities.
    "READ_PHONE_STATE": (3, "Telephony", "Reads device identifiers (IMEI, number)"),
    "READ_PHONE_NUMBERS": (5, "Telephony", "Reads the device phone number"),
    "READ_CALL_LOG": (10, "Telephony", "Reads call history"),
    "CALL_PHONE": (8, "Telephony", "Can place calls — toll fraud"),
    "PROCESS_OUTGOING_CALLS": (8, "Telephony", "Intercepts outgoing calls"),

    # Dropper / persistence
    "REQUEST_INSTALL_PACKAGES": (5, "Dropper", "Can request APK installation — legitimate in stores/file managers; dropper-relevant with payload loading"),
    "QUERY_ALL_PACKAGES": (2, "Recon", "Enumerates installed apps — legitimate for launchers/password tools; contextual targeting evidence"),
    "REQUEST_DELETE_PACKAGES": (8, "Dropper", "Can uninstall apps — disable security tools"),
    "RECEIVE_BOOT_COMPLETED": (3, "Persistence", "Starts on boot — common scheduling capability; contextual persistence evidence"),
    "FOREGROUND_SERVICE": (0, "Persistence", "Long-running foreground service — common and report-only"),
    "BIND_DEVICE_ADMIN": (15, "DeviceAdmin", "Device admin — lock/wipe, anti-removal"),

    # Surveillance
    "RECORD_AUDIO": (5, "Surveillance", "Microphone access — recording/eavesdropping capability"),
    "CAMERA": (2, "Surveillance", "Camera access"),
    "ACCESS_FINE_LOCATION": (3, "Surveillance", "Precise location tracking"),
    "ACCESS_BACKGROUND_LOCATION": (5, "Surveillance", "Background location tracking"),
    "READ_NOTIFICATION_POLICY": (6, "Notifications", "Notification access — OTP/alert stealing"),

    # Storage / network (lower weight; context matters)
    "READ_EXTERNAL_STORAGE": (1, "Storage", "Reads external storage"),
    "WRITE_EXTERNAL_STORAGE": (0, "Storage", "Writes external storage — legacy and report-only"),
    "MANAGE_EXTERNAL_STORAGE": (3, "Storage", "Full external storage access"),
    # INTERNET and ACCESS_NETWORK_STATE are intentionally absent: almost every modern
    # application requests them, so they are context inputs rather than risk findings.
}


def _short(permission: str) -> str:
    """android.permission.READ_SMS -> READ_SMS"""
    return permission.rsplit(".", 1)[-1].strip()


def analyze_permissions(permissions):
    """Return findings + the permission contribution to the risk score.

    permissions: list of full permission strings from the manifest.
    """
    findings = []
    seen = set()
    for perm in permissions or []:
        short = _short(perm)
        if short in seen:
            continue
        seen.add(short)
        if short in DANGEROUS_PERMISSIONS:
            score, category, why = DANGEROUS_PERMISSIONS[short]
            findings.append({
                "permission": perm,
                "name": short,
                "category": category,
                "score": score,
                "reason": why,
            })

    # Sort most dangerous first for nicer presentation.
    findings.sort(key=lambda f: f["score"], reverse=True)
    return {
        "all_permissions": sorted(set(permissions or [])),
        "dangerous": findings,
        "dangerous_count": len(findings),
    }
