"""APKiD integration — compiler / packer / obfuscator / anti-analysis fingerprinting.

APKiD ("PEiD for Android") fingerprints *how* an APK was built and what is hiding it.
A normal Play-Store app is compiled with r8/d8; an app assembled with dexlib was
repackaged, and packers/protectors/anti-analysis tricks strongly correlate with
malware. This complements the heuristic obfuscation module with named tooling.

Optional: if apkid is not importable, `available()` is False and the analyzer skips it.
"""
import logging
import threading

log = logging.getLogger("apkid")

_scanner = None
_load_attempted = False
_load_lock = threading.Lock()
_scan_lock = threading.Lock()

# tag (APKiD rule category) -> (score, human label).
# NOTE: 'obfuscator' is intentionally NOT scored — APKiD reports standard R8/ProGuard
# name-shortening as an obfuscator, which is normal for every release build. We report
# obfuscator/compiler findings but only *score* genuinely-suspicious tooling (packers,
# protectors, anti-analysis, droppers).
_TAG_WEIGHTS = {
    "packer": (15, "Packer"),
    "protector": (12, "Protector"),
    # Anti-VM/anti-debug are individually noisy — e.g. reading Build.FINGERPRINT (common
    # in benign crash-reporting) trips APKiD's anti-VM rules — so weighted low.
    "anti_vm": (0, "Anti-VM"),
    "anti_debug": (0, "Anti-debug"),
    "anti_disassembly": (6, "Anti-disassembly"),
    "dropper": (15, "Dropper"),
    "abnormal": (4, "Abnormal structure"),
}
# Reported but not scored (too common / benign in normal release builds).
_REPORT_ONLY_TAGS = {"obfuscator", "manipulator"}
_SKIP_TAGS = {"file_type"}
_TAG_CAPS = {
    # Multiple Build.* checks are usually one library's emulator-detection routine, not
    # independent evidence. Cap noisy categories across the whole APK.
    "anti_vm": 3,
    "anti_debug": 3,
}


def available() -> bool:
    try:
        import apkid  # noqa: F401
        return True
    except Exception:
        return False


def _get_scanner():
    global _scanner, _load_attempted
    if _load_attempted:
        return _scanner
    with _load_lock:
        if _load_attempted:
            return _scanner
        try:
            from apkid.apkid import Scanner, Options
            from apkid.rules import RulesManager
            opts = Options(timeout=30, verbose=False, json=True, typing="magic")
            rules = RulesManager().load()
            _scanner = Scanner(rules, opts)
        except Exception as e:
            log.error("Failed to initialise APKiD: %s", e)
            _scanner = None
        finally:
            _load_attempted = True
    return _scanner


def scan(apk_path: str) -> dict:
    if not available():
        return {"available": False, "findings": [], "score": 0}

    scanner = _get_scanner()
    if scanner is None:
        return {"available": True, "findings": [], "score": 0, "error": "APKiD rules failed to load"}

    try:
        # APKiD's Scanner owns native rule state; keep one shared scanner but do not
        # enter it concurrently from bounded batch worker threads.
        with _scan_lock:
            raw = scanner.scan_file(apk_path)
    except Exception as e:
        log.exception("APKiD scan failed")
        return {"available": True, "findings": [], "score": 0, "error": str(e)}

    seen = set()
    findings = []
    compilers = []
    score = 0
    tag_scores = {}
    for entry, matches in (raw or {}).items():
        for m in matches:
            tags = list(getattr(m, "tags", []) or [])
            desc = (dict(getattr(m, "meta", {}) or {})).get("description", m.rule)
            primary = next((t for t in tags if t not in _SKIP_TAGS), None)

            # Track compiler separately; flag repackaging tools (dexlib/dexmerge/jadx),
            # which indicate a decompiled-and-reassembled app — a real malware signal,
            # but a normal r8/d8 compiler is benign and only reported.
            if "compiler" in tags:
                low = desc.lower()
                if any(k in low for k in ("dexlib", "dexmerge", "jadx", "apktool")):
                    key = ("manipulator", desc)
                    if key not in seen:
                        seen.add(key)
                        findings.append({"category": "Manipulator / repackaging", "name": desc,
                                         "detail": "assembled with a repackaging tool", "score": 8})
                        score += 8
                elif "unknown" not in low:
                    compilers.append(desc)
                continue

            if primary in _TAG_WEIGHTS:
                pts, label = _TAG_WEIGHTS[primary]
                key = (primary, desc)
                if key in seen:
                    continue
                seen.add(key)
                cap = _TAG_CAPS.get(primary, 30)
                awarded = min(pts, max(0, cap - tag_scores.get(primary, 0)))
                tag_scores[primary] = tag_scores.get(primary, 0) + awarded
                findings.append({"category": label, "name": desc,
                                 "detail": entry.split("!")[-1], "score": awarded})
                score += awarded
            elif primary in _REPORT_ONLY_TAGS:
                key = (primary, desc)
                if key not in seen:
                    seen.add(key)
                    findings.append({"category": primary.title(), "name": desc,
                                     "detail": "normal for release builds", "score": 0})

    score = min(score, 30)
    return {
        "available": True,
        "findings": findings,
        "compilers": sorted(set(compilers)),
        "score": score,
        "count": len(findings),
    }
