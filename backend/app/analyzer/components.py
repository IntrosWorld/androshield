"""Exported-component (attack-surface) analysis.

Exported activities/services/receivers/providers are reachable by other apps. A
launcher activity is exported by design, but exported services/receivers/providers
*without a permission guard* are a real attack surface (and a vuln-scanner angle, not
just malware). Reads the manifest XML directly via androguard.
"""
import logging

log = logging.getLogger("components")

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _attr(el, name):
    return el.get(ANDROID_NS + name)


def analyze_components(apk):
    result = {"exported": [], "count": 0, "score": 0}
    try:
        manifest = apk.get_android_manifest_xml()
    except Exception as e:
        result["error"] = str(e)
        return result
    if manifest is None:
        return result

    score = 0
    exported = []
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in manifest.iter(kind):
            name = _attr(el, "name") or ""
            exported_attr = _attr(el, "exported")
            has_intent_filter = el.find("intent-filter") is not None
            permission = _attr(el, "permission")

            if exported_attr is not None:
                is_exported = exported_attr.lower() == "true"
            else:
                # Implicitly exported when it declares an intent-filter (pre-Android 12).
                is_exported = has_intent_filter
            if not is_exported:
                continue

            entry = {
                "type": kind,
                "name": name,
                "has_permission": bool(permission),
                "has_intent_filter": has_intent_filter,
            }
            exported.append(entry)

            # Score unguarded non-activity surfaces (providers leak data; receivers/
            # services accept external intents). Launcher activities are expected.
            if kind in ("service", "receiver", "provider") and not permission:
                score += 4 if kind == "provider" else 2

    result["exported"] = exported
    result["count"] = len(exported)
    result["unguarded_count"] = sum(
        1 for e in exported
        if e["type"] in ("service", "receiver", "provider") and not e["has_permission"])
    result["score"] = min(score, 10)
    return result
