"""Suspicious Android API detection with invocation-aware evidence.

The detector deliberately distinguishes an observed method call from a class or
method name that merely exists in the DEX string pool. Bundled libraries contain many
security-sensitive framework descriptors without using the risky operation; treating
those descriptors as calls caused both false positives and misleading labels.
"""
import re


# label, class regex, method regex, invoked score, reference-only score, behaviour
#
# A reference-only score is intentionally small and reserved for capabilities where a
# class reference is useful evidence even when androguard cannot recover a callsite
# (common with reflection, inheritance, malformed DEX, and the synthetic fixture).
API_SIGNATURES = [
    ("SmsManager.sendTextMessage", r"Landroid/telephony/(?:gsm/)?SmsManager;",
     r"send(?:Text|MultipartText)Message", 15, 4,
     "Sends SMS programmatically — OTP relay / premium fraud"),
    ("AccessibilityService", r"Landroid/accessibilityservice/AccessibilityService;",
     r".*", 18, 6,
     "Accessibility automation — screen scraping / auto-click fraud"),
    ("NotificationListenerService", r"Landroid/service/notification/NotificationListenerService;",
     r".*", 5, 1,
     "Reads notifications — legitimate in wearables/launchers; OTP risk needs fraud context"),
    ("DexClassLoader", r"Ldalvik/system/DexClassLoader;", r"<init>|loadClass",
     12, 4, "Dynamic code loading — hides second-stage payload"),
    ("Runtime.exec", r"Ljava/lang/Runtime;", r"exec", 3, 0,
     "Shell command execution"),
    ("ProcessBuilder", r"Ljava/lang/ProcessBuilder;", r"<init>|start", 3, 0,
     "Process spawning — command execution"),
    ("DevicePolicyManager abuse", r"Landroid/app/admin/DevicePolicyManager;",
     r"lockNow|wipeData|resetPassword|setActiveAdmin|setDeviceOwner", 6, 0,
     "High-impact device-admin operation — lock/wipe / anti-removal"),
    ("Raw Socket", r"Ljava/net/Socket;", r"<init>|connect|getOutputStream", 0, 0,
     "Direct network socket — common in network clients; relevant with suspicious endpoints"),
    ("PathClassLoader", r"Ldalvik/system/PathClassLoader;", r"<init>|loadClass", 3, 1,
     "Dynamic class loading"),
    ("Clipboard read", r"Landroid/content/ClipboardManager;",
     r"getPrimaryClip|getText|hasPrimaryClip", 1, 0,
     "Reads clipboard data — common in editors/password tools; contextual OTP evidence"),
    ("Telephony identifiers", r"Landroid/telephony/TelephonyManager;",
     r"getDeviceId|getImei|getMeid|getLine1Number|getSubscriberId|"
     r"getSimSerialNumber", 1, 0,
     "Reads device/subscriber identifiers — fingerprinting"),
    ("WebView.addJavascriptInterface", r"Landroid/webkit/WebView;",
     r"addJavascriptInterface", 1, 0,
     "Exposes a Java object to WebView JavaScript — risky in untrusted content"),
    ("Settings.canDrawOverlays", r"Landroid/provider/Settings;", r"canDrawOverlays", 2, 0,
     "Checks overlay permission — overlay attack setup"),
    ("PackageManager.setComponentEnabledSetting", r"Landroid/content/pm/PackageManager;",
     r"setComponentEnabledSetting", 1, 0,
     "Component toggling — may hide launcher icon"),
    ("HttpURLConnection", r"Ljava/net/HttpURLConnection;",
     r"connect|getInputStream|getOutputStream", 0, 0,
     "HTTP communication — possible C2 / exfiltration"),
    ("OkHttp", r"Lokhttp3/", r"newCall|execute|enqueue", 0, 0,
     "HTTP client — possible C2 / exfiltration"),
    ("Cipher operation", r"Ljavax/crypto/Cipher;", r"init|doFinal", 0, 0,
     "Cryptographic operation — may protect data or conceal payloads"),
]

_COMPILED = [
    (label, re.compile(class_rx), re.compile(method_rx), score, ref_score, behaviour)
    for label, class_rx, method_rx, score, ref_score, behaviour in API_SIGNATURES
]

# Dynamic loading performed wholly inside common SDK namespaces is normally module or
# resource loading, not an app-controlled second stage. Keep it visible, but require at
# least one first-party caller before scoring it as dropper evidence.
_COMMON_LIBRARY_PREFIXES = (
    "Landroid/", "Landroidx/", "Lcom/android/", "Lcom/google/android/gms/",
    "Lcom/google/firebase/", "Lcom/facebook/", "Lcom/unity3d/", "Lokhttp3/",
    "Lorg/apache/", "Lkotlin/", "Lkotlinx/",
)


def _library_caller(caller: str) -> bool:
    return caller.startswith(_COMMON_LIBRARY_PREFIXES)


def _callers(method_analysis):
    """Return stable caller labels for an androguard MethodAnalysis object."""
    try:
        xrefs = list(method_analysis.get_xref_from())
    except Exception:
        return []
    callers = []
    for xref in xrefs:
        try:
            caller = xref[1]
            callers.append(f"{caller.class_name}->{caller.name}")
        except Exception:
            callers.append("unknown caller")
    return sorted(set(callers))


def analyze_apis(dx, dex_strings):
    """Detect invoked APIs and lower-confidence reference-only capabilities.

    ``dx`` is the androguard Analysis object and may be ``None``. Findings include a
    confidence/evidence_type field so downstream scoring and reports never describe a
    string-pool reference as an observed method invocation.
    """
    findings = []
    string_blob = "\n".join(str(s) for s in (dex_strings or []) if s)

    for label, class_rx, method_rx, invoked_score, ref_score, behaviour in _COMPILED:
        callers = []
        if dx is not None:
            try:
                for method in dx.find_methods(
                        classname=class_rx.pattern, methodname=method_rx.pattern):
                    callers.extend(_callers(method))
            except Exception:
                callers = []
        callers = sorted(set(callers))

        if callers:
            library_only = label in {"DexClassLoader", "PathClassLoader"} and all(
                _library_caller(caller) for caller in callers
            )
            findings.append({
                "api": label,
                "score": 0 if library_only else invoked_score,
                "behaviour": behaviour,
                "evidence": (f"{len(callers)} common-library call site(s); report-only"
                             if library_only else f"{len(callers)} call site(s)"),
                "evidence_type": "invoked",
                "confidence": "medium" if library_only else "high",
                "callers": callers[:8],
                "library_context": library_only,
            })
            continue

        # A reference requires both the class and the specific method token. For
        # capability classes whose method regex is `.*`, the class descriptor suffices.
        class_seen = bool(string_blob and class_rx.search(string_blob))
        method_seen = method_rx.pattern == ".*" or bool(method_rx.search(string_blob))
        if ref_score > 0 and class_seen and method_seen:
            findings.append({
                "api": label,
                "score": ref_score,
                "behaviour": behaviour,
                "evidence": "class/method referenced; no callsite recovered",
                "evidence_type": "reference",
                "confidence": "low",
                "callers": [],
            })

    findings.sort(key=lambda f: (f["score"], f["confidence"] == "high"), reverse=True)
    return {
        "suspicious_apis": findings,
        "count": len(findings),
        "invoked_count": sum(f["evidence_type"] == "invoked" for f in findings),
        "reference_count": sum(f["evidence_type"] == "reference" for f in findings),
    }
