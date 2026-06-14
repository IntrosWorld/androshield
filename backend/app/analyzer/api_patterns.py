"""Suspicious Android API detection.

We look for framework classes/methods whose use correlates with fraud behaviour.
Detection is done two ways for robustness:
  1. androguard Analysis.find_methods(class_regex) with cross-references (the app
     actually *invokes* the API), and
  2. a fallback substring scan over the raw DEX-defined strings/descriptors for the
     same smali class signature.

Each signature: (label, smali_class_regex, score, behaviour).
smali_class_regex matches the Dalvik type descriptor, e.g. 'Landroid/telephony/SmsManager;'.
"""
import re

# label, class_regex (Dalvik descriptor), score, behaviour
#
# Weights are TIERED by how discriminating the API is. Many framework classes
# (Base64, reflection, WebView, HttpURLConnection, Cipher) appear in nearly every app
# via bundled libraries (AndroidX/Kotlin), so merely referencing them is NOT suspicious
# — those are weighted ~0. Only APIs that are genuinely rare in benign apps and central
# to banking-fraud (SMS sending, accessibility automation, notification listening,
# runtime DEX loading) carry real weight.
API_SIGNATURES = [
    # --- High-signal: rare in benign apps, core fraud capabilities ---
    ("SmsManager.sendTextMessage", r"Landroid/telephony/SmsManager;", 15,
     "Sends SMS programmatically — OTP relay / premium fraud"),
    ("SmsManager (read/observe)", r"Landroid/telephony/gsm/SmsManager;", 10,
     "Legacy SMS API usage"),
    ("AccessibilityService", r"Landroid/accessibilityservice/AccessibilityService;", 18,
     "Accessibility automation — screen scraping / auto-click fraud"),
    ("NotificationListenerService", r"Landroid/service/notification/NotificationListenerService;", 15,
     "Reads notifications — OTP / banking alert stealing"),
    ("DexClassLoader", r"Ldalvik/system/DexClassLoader;", 12,
     "Dynamic code loading — hides second-stage payload"),
    # --- Medium-signal: suspicious in context ---
    ("Runtime.exec", r"Ljava/lang/Runtime;", 3,
     "Shell command execution"),
    ("ProcessBuilder", r"Ljava/lang/ProcessBuilder;", 4,
     "Process spawning — command execution"),
    ("DevicePolicyManager", r"Landroid/app/admin/DevicePolicyManager;", 3,
     "Device admin control — lock/wipe / anti-removal"),
    ("Raw Socket", r"Ljava/net/Socket;", 4,
     "Raw socket — custom C2 channel"),
    ("PathClassLoader", r"Ldalvik/system/PathClassLoader;", 3,
     "Dynamic class loading"),
    ("ClipboardManager", r"Landroid/content/ClipboardManager;", 3,
     "Clipboard access — steals copied OTPs / crypto addresses"),
    ("TelephonyManager.getDeviceId", r"Landroid/telephony/TelephonyManager;", 3,
     "Reads device identifiers — fingerprinting"),
    # --- Low-signal / ubiquitous (present via libraries in most apps) ---
    ("WebView.addJavascriptInterface", r"Landroid/webkit/WebView;", 2,
     "WebView JS bridge — phishing page / JS injection"),
    ("canDrawOverlays", r"Landroid/provider/Settings;", 2,
     "Checks overlay permission — overlay attack setup"),
    ("PackageManager.setComponentEnabled", r"Landroid/content/pm/PackageManager;", 1,
     "Component toggling — may hide launcher icon"),
    ("HttpURLConnection", r"Ljava/net/HttpURLConnection;", 1,
     "HTTP communication — possible C2 / exfiltration"),
    ("OkHttp", r"Lokhttp3/", 1,
     "HTTP client — possible C2 / exfiltration"),
    ("Cipher (crypto)", r"Ljavax/crypto/Cipher;", 1,
     "Encryption — may obfuscate exfiltrated data"),
    ("Base64", r"Landroid/util/Base64;", 0,
     "Base64 encoding — string/payload obfuscation"),
    ("Reflection (Method.invoke)", r"Ljava/lang/reflect/Method;", 0,
     "Reflection — obfuscates real API calls"),
]

_COMPILED = [(label, re.compile(rx), score, behaviour)
             for label, rx, score, behaviour in API_SIGNATURES]


def analyze_apis(dx, dex_strings):
    """Detect suspicious API usage.

    dx: androguard Analysis object (may be None).
    dex_strings: iterable of raw DEX strings (fallback scan).
    """
    findings = []
    string_blob = "\n".join(dex_strings) if dex_strings else ""

    for label, rx, score, behaviour in _COMPILED:
        used = False
        evidence = ""

        # 1) Proper xref-based detection via androguard.
        if dx is not None:
            try:
                for m in dx.find_methods(classname=rx.pattern):
                    # A referenced method with callers means the API is actually used.
                    try:
                        xrefs = list(m.get_xref_from())
                    except Exception:
                        xrefs = []
                    used = True
                    if xrefs:
                        evidence = f"{len(xrefs)} call site(s)"
                        break
            except Exception:
                pass

        # 2) Fallback substring scan over DEX strings/descriptors.
        if not used and string_blob and rx.search(string_blob):
            used = True
            evidence = "referenced in DEX strings"

        # Score 0 = ubiquitous library class; not worth reporting as suspicious.
        if used and score > 0:
            findings.append({
                "api": label,
                "score": score,
                "behaviour": behaviour,
                "evidence": evidence or "class referenced",
            })

    findings.sort(key=lambda f: f["score"], reverse=True)
    return {"suspicious_apis": findings, "count": len(findings)}
