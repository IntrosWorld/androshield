"""YARA signature scanning (offline).

Compiles the bundled ruleset once and scans a TEXT blob built from the APK's
decompiled DEX strings + declared permissions + package name. Optional: if
yara-python is not installed, `available()` is False and the analyzer skips this
stage gracefully.
"""
import logging
import os

log = logging.getLogger("yara_scan")

_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "android_fraud.yar")
_compiled = None
_load_attempted = False


def available() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except Exception:
        return False


def _rules():
    global _compiled, _load_attempted
    if _load_attempted:
        return _compiled
    _load_attempted = True
    try:
        import yara
        _compiled = yara.compile(filepath=os.path.abspath(_RULES_PATH))
    except Exception as e:
        log.error("Failed to compile YARA rules: %s", e)
        _compiled = None
    return _compiled


def _matched_identifiers(match):
    """Extract string identifiers across yara-python API versions.

    Newer yara-python: match.strings is a list of StringMatch objects (.identifier).
    Older yara-python / yara-python-dex: list of (offset, identifier, data) tuples.
    """
    ids = set()
    for s in getattr(match, "strings", []) or []:
        ident = getattr(s, "identifier", None)
        if ident is None and isinstance(s, (tuple, list)) and len(s) >= 2:
            ident = s[1]
        if isinstance(ident, bytes):
            ident = ident.decode("utf-8", "ignore")
        if ident:
            ids.add(ident)
    return sorted(ids)[:10]


def scan(dex_strings, permissions=None, package_name=""):
    """Return matched rules + their contribution to the risk score."""
    if not available():
        return {"available": False, "matches": [], "score": 0}

    rules = _rules()
    if rules is None:
        return {"available": True, "matches": [], "score": 0, "error": "rules failed to compile"}

    blob_parts = list(dex_strings or [])
    blob_parts += list(permissions or [])
    if package_name:
        blob_parts.append(package_name)
    blob = "\n".join(p for p in blob_parts if p)

    matches = []
    score = 0
    try:
        for m in rules.match(data=blob):
            meta = m.meta or {}
            rule_score = 0
            try:
                rule_score = int(meta.get("score", 0))
            except (TypeError, ValueError):
                rule_score = 0
            score += rule_score
            matches.append({
                "rule": m.rule,
                "description": meta.get("description", ""),
                "severity": meta.get("severity", ""),
                "attack": meta.get("attack", ""),
                "score": rule_score,
                "matched_strings": _matched_identifiers(m),
            })
    except Exception as e:
        log.exception("YARA scan failed")
        return {"available": True, "matches": [], "score": 0, "error": str(e)}

    score = min(score, 40)  # cap YARA contribution
    matches.sort(key=lambda x: x["score"], reverse=True)
    return {"available": True, "matches": matches, "score": score, "count": len(matches)}
