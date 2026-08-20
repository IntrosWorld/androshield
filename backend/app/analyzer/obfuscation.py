"""Obfuscation / packing signals.

Fraud APKs frequently hide logic. We score several cheap-to-compute signals:
short class names, multiple DEX files, native libraries, dynamic loading /
reflection, and high-entropy strings.
"""
import math
import re
from collections import Counter


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_SHORT_NAME_RE = re.compile(r"^[a-z]{1,2}$")


def analyze_obfuscation(apk, dex_list, dex_strings, api_result=None):
    signals = []
    score = 0

    # --- Multiple DEX files ---
    try:
        dex_count = len(dex_list) if dex_list else 0
    except Exception:
        dex_count = 0
    if dex_count > 1:
        # Multi-DEX is routine once an app exceeds Android's method limit. Keep it as
        # coverage metadata, never standalone evasion evidence.
        signals.append({"signal": "Multiple DEX files", "detail": f"{dex_count} dex files", "score": 0})

    # --- Native libraries (.so) ---
    native_libs = []
    try:
        native_libs = [f for f in apk.get_files() if f.endswith(".so")]
    except Exception:
        pass
    if native_libs:
        # Native code is common in games, media, crypto, and ML apps. Report it as an
        # analysis blind spot, but do not treat its mere presence as obfuscation.
        signals.append({"signal": "Native libraries", "detail": f"{len(native_libs)} .so file(s)", "score": 0})

    # --- Short / meaningless class names ---
    short_classes = 0
    total_classes = 0
    try:
        for dex in (dex_list or []):
            for cls in dex.get_classes():
                total_classes += 1
                name = cls.get_name()  # e.g. 'La/b/c;'
                last = name.strip("L;").split("/")[-1]
                if _SHORT_NAME_RE.match(last):
                    short_classes += 1
    except Exception:
        pass
    if total_classes:
        ratio = short_classes / total_classes
        # R8/ProGuard minification shortens names in nearly every *release* app, so this
        # is only weakly suspicious and needs a high ratio before it counts at all.
        if ratio > 0.55:
            pts = 5 if ratio > 0.75 else 2
            signals.append({
                "signal": "Heavy name obfuscation",
                "detail": f"{short_classes}/{total_classes} classes have 1-2 char names ({ratio:.0%})",
                "score": pts,
            })
            score += pts

    # --- Dynamic loading / reflection in strings ---
    # Note: reflection and System.loadLibrary are excluded — they appear in almost every
    # app via AndroidX/Kotlin and are not, by themselves, obfuscation signals.
    blob = "\n".join(dex_strings) if dex_strings else ""
    api_result = api_result or {}
    api_findings = {item.get("api"): item for item in api_result.get("suspicious_apis", [])}
    for marker, api_name, label, pts in [
        ("DexClassLoader", "DexClassLoader", "Dynamic DEX loading", 8),
        ("Ldalvik/system/InMemoryDexClassLoader", "InMemoryDexClassLoader", "In-memory DEX loading", 8),
    ]:
        if marker in blob:
            finding = api_findings.get(api_name, {})
            library_only = finding.get("library_context") is True
            applied = 0 if library_only else pts
            detail = (f"`{marker}` used only by a common library; report-only"
                      if library_only else f"`{marker}` present")
            signals.append({"signal": label, "detail": detail, "score": applied})
            score += applied

    # --- High-entropy strings (likely encrypted blobs) ---
    high_entropy = 0
    entropy_candidates = 0
    for s in (dex_strings or []):
        if 24 <= len(s) <= 512 and " " not in s:
            entropy_candidates += 1
            if _shannon_entropy(s) > 4.5:
                high_entropy += 1
    entropy_ratio = high_entropy / entropy_candidates if entropy_candidates else 0.0
    # Absolute counts scale with app/library size. A ratio prevents large ad-heavy apps
    # from looking packed simply because they contain hundreds of hashes and identifiers.
    if high_entropy >= 25 and entropy_ratio >= 0.35:
        pts = 5 if entropy_ratio >= 0.60 else 2
        signals.append({
            "signal": "High-entropy strings",
            "detail": (f"{high_entropy}/{entropy_candidates} candidate strings are "
                       f"high entropy ({entropy_ratio:.0%})"),
            "score": pts,
        })
        score += pts

    # Cap the obfuscation sub-score.
    score = min(score, 18)
    return {
        "signals": signals,
        "score": score,
        "dex_count": dex_count,
        "native_libs": native_libs[:50],
        "high_entropy_count": high_entropy,
        "high_entropy_ratio": round(entropy_ratio, 4),
        "is_obfuscated": score >= 10,
    }
