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
    "SYSTEM_ALERT_WINDOW": (12, "Overlay",
                            "Draw-over-other-apps — fake login overlay attacks"),

    # Contacts — victim spreading / phishing
    "READ_CONTACTS": (10, "Contacts", "Reads contacts — phishing / spreading"),
    "WRITE_CONTACTS": (6, "Contacts", "Modifies contacts"),
    "GET_ACCOUNTS": (6, "Contacts", "Enumerates device accounts"),

    # Telephony / identity
    "READ_PHONE_STATE": (8, "Telephony", "Reads device identifiers (IMEI, number)"),
    "READ_PHONE_NUMBERS": (8, "Telephony", "Reads the device phone number"),
    "READ_CALL_LOG": (10, "Telephony", "Reads call history"),
    "CALL_PHONE": (8, "Telephony", "Can place calls — toll fraud"),
    "PROCESS_OUTGOING_CALLS": (8, "Telephony", "Intercepts outgoing calls"),

    # Dropper / persistence
    "REQUEST_INSTALL_PACKAGES": (15, "Dropper", "Can install APKs — dropper / second stage"),
    "QUERY_ALL_PACKAGES": (8, "Recon", "Enumerates all installed apps — targets banking apps"),
    "REQUEST_DELETE_PACKAGES": (8, "Dropper", "Can uninstall apps — disable security tools"),
    "RECEIVE_BOOT_COMPLETED": (6, "Persistence", "Starts on boot — persistence"),
    "FOREGROUND_SERVICE": (4, "Persistence", "Long-running foreground service"),
    "BIND_DEVICE_ADMIN": (15, "DeviceAdmin", "Device admin — lock/wipe, anti-removal"),

    # Surveillance
    "RECORD_AUDIO": (10, "Surveillance", "Microphone access — eavesdropping"),
    "CAMERA": (8, "Surveillance", "Camera access"),
    "ACCESS_FINE_LOCATION": (6, "Surveillance", "Precise location tracking"),
    "ACCESS_BACKGROUND_LOCATION": (8, "Surveillance", "Background location tracking"),
    "READ_NOTIFICATION_POLICY": (6, "Notifications", "Notification access — OTP/alert stealing"),

    # Storage / network (lower weight; context matters)
    "READ_EXTERNAL_STORAGE": (4, "Storage", "Reads external storage"),
    "WRITE_EXTERNAL_STORAGE": (4, "Storage", "Writes external storage"),
    "MANAGE_EXTERNAL_STORAGE": (8, "Storage", "Full external storage access"),
    "INTERNET": (5, "Network", "Network access — data exfiltration channel"),
    "ACCESS_NETWORK_STATE": (1, "Network", "Reads network state"),
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
