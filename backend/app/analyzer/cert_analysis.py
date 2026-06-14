"""Signing-certificate analysis.

Most Android apps are self-signed (that's normal), so self-signing alone isn't scored.
We flag the genuinely suspicious patterns: a debug certificate on a distributed app,
generic/placeholder issuer fields, and absurd validity windows.
"""
import hashlib
import logging

log = logging.getLogger("cert_analysis")


def _human(field):
    try:
        return field.human_friendly
    except Exception:
        return str(field)


def analyze_certificate(apk):
    info = {"present": False, "flags": [], "score": 0}
    try:
        certs = apk.get_certificates()
    except Exception as e:
        info["error"] = str(e)
        return info
    if not certs:
        info["flags"].append({"flag": "Unsigned", "detail": "No signing certificate found",
                              "score": 5})
        info["score"] = 5
        return info

    c = certs[0]
    info["present"] = True
    info["subject"] = _human(getattr(c, "subject", ""))
    info["issuer"] = _human(getattr(c, "issuer", ""))
    try:
        info["serial"] = str(c.serial_number)
    except Exception:
        info["serial"] = ""

    # SHA-1/SHA-256 of the DER (the cert fingerprint used in blocklists).
    try:
        der = apk.get_certificate_der(apk.get_signature_name())
        if der:
            info["sha1"] = hashlib.sha1(der).hexdigest()
            info["sha256"] = hashlib.sha256(der).hexdigest()
    except Exception:
        pass

    # Validity window.
    not_before = not_after = None
    try:
        validity = c["tbs_certificate"]["validity"]
        not_before = validity["not_before"].native
        not_after = validity["not_after"].native
        info["not_before"] = str(not_before)
        info["not_after"] = str(not_after)
        years = (not_after - not_before).days / 365.25
        info["validity_years"] = round(years, 1)
    except Exception:
        years = None

    try:
        info["self_signed"] = c.self_signed in ("yes", "maybe")
    except Exception:
        info["self_signed"] = None

    score = 0
    subj = (info.get("subject") or "").lower()

    # Debug certificate on a real sample is a strong tell.
    if "android debug" in subj or "cn=android debug" in subj:
        info["flags"].append({"flag": "Debug certificate",
                              "detail": "Signed with the Android debug key", "score": 10})
        score += 10

    # Generic / placeholder identity.
    if any(p in subj for p in ("unknown", "cn=test", "o=test", "example")):
        info["flags"].append({"flag": "Placeholder identity",
                              "detail": f"Generic cert subject: {info.get('subject')}", "score": 5})
        score += 5

    # Absurd validity (extremely long or already expired-at-signing).
    if years is not None:
        if years > 100:
            info["flags"].append({"flag": "Implausible validity",
                                  "detail": f"{info['validity_years']} year validity", "score": 4})
            score += 4
        elif years < 1:
            info["flags"].append({"flag": "Very short validity",
                                  "detail": f"{info['validity_years']} year validity", "score": 4})
            score += 4

    info["score"] = min(score, 12)
    return info
