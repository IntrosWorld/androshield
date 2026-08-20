"""Static analysis orchestrator built on androguard (pure-Python, no Java deps).

`analyze(apk_path)` returns a single dict combining manifest metadata, permissions,
suspicious APIs, IOCs, obfuscation signals, the rule-based risk score and derived
behaviour labels. Every stage is defensive: a failure in one stage degrades to a
partial result rather than crashing the request.
"""
import hashlib
import logging
import os

from . import (api_patterns, cert_analysis, components, iocs, mitre, obfuscation,
               permissions, risk_scoring, yara_scan)
from ..intel import apkid_scan
from ..ml import classifier as ml_classifier

import re as _re

_ASCII_RE = _re.compile(rb"[\x20-\x7e]{5,}")

log = logging.getLogger("static_analyzer")


def engine_available() -> bool:
    """True if the static-analysis engine (androguard) can be imported."""
    try:
        import androguard.misc  # noqa: F401
        return True
    except Exception:
        return False


def _hashes(path):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def _safe(fn, default):
    try:
        v = fn()
        return v if v is not None else default
    except Exception:
        return default


def _collect_dex_strings(dex_list, dx):
    """Gather decompiled strings from all DEX files (de-duplicated, bounded)."""
    strings = set()
    try:
        for dex in (dex_list or []):
            for s in _safe(dex.get_strings, []):
                if s:
                    strings.add(s)
    except Exception:
        pass
    # androguard Analysis also exposes string-analysis objects.
    if dx is not None:
        try:
            for sa in dx.get_strings():
                val = getattr(sa, "get_value", lambda: None)()
                if val:
                    strings.add(val)
        except Exception:
            pass
    return list(strings)


def _collect_raw_dex_strings(apk, max_files=8, max_total_bytes=32 * 1024 * 1024,
                             cap=12000):
    """Recover bounded printable strings when bytecode decoding fails.

    This fallback reads archive entries only; it never interprets or executes DEX
    instructions. Bounds prevent malformed or oversized samples exhausting memory.
    """
    strings = set()
    total_bytes = 0
    try:
        dex_files = [name for name in apk.get_files() if name.casefold().endswith(".dex")]
    except Exception:
        return []
    for name in dex_files[:max_files]:
        try:
            data = apk.get_file(name)
        except Exception:
            continue
        if not data or total_bytes + len(data) > max_total_bytes:
            continue
        total_bytes += len(data)
        for match in _ASCII_RE.findall(data):
            value = match.decode("ascii", "ignore")
            if value:
                strings.add(value)
            if len(strings) >= cap:
                return list(strings)
    return list(strings)


def _collect_native_strings(apk, max_files=8, max_bytes=8 * 1024 * 1024, cap=4000):
    """Extract printable ASCII strings from bundled .so native libraries.

    Malware often hides C2 URLs / keywords in native code where a DEX-string scan
    won't see them. Bounded to keep large libraries from blowing up memory/time.
    """
    out = []
    try:
        so_files = [f for f in apk.get_files() if f.endswith(".so")][:max_files]
    except Exception:
        return out
    for name in so_files:
        try:
            data = apk.get_file(name)
        except Exception:
            continue
        if not data or len(data) > max_bytes:
            continue
        for m in _ASCII_RE.findall(data):
            out.append(m.decode("ascii", "ignore"))
            if len(out) >= cap:
                return out
    return out


def analyze(apk_path: str) -> dict:
    result = {
        "file": {
            "filename": os.path.basename(apk_path),
            "file_size": _safe(lambda: os.path.getsize(apk_path), 0),
        },
        "errors": [],
    }

    sha256, md5 = _hashes(apk_path)
    result["file"]["sha256"] = sha256
    result["file"]["md5"] = md5

    # --- Parse the APK with androguard ---
    a = dex_list = dx = None
    analysis_quality = "full"
    try:
        from androguard.misc import AnalyzeAPK
        a, dex_list, dx = AnalyzeAPK(apk_path)
        # AnalyzeAPK may return a single DalvikVMFormat or a list; normalise.
        if dex_list is not None and not isinstance(dex_list, (list, tuple)):
            dex_list = [dex_list]
    except ImportError as e:
        # The analysis engine itself is missing — this is an environment error,
        # NOT a verdict about the APK. Never report this as "Low".
        log.error("androguard not importable: %s", e)
        raise RuntimeError(
            "Static-analysis engine unavailable: androguard could not be imported. "
            "Start the server from backend/.venv (where dependencies are installed)."
        ) from e
    except Exception as e:
        # Malformed DEX should not discard recoverable manifest/string evidence.
        log.warning("Full DEX analysis failed; trying partial fallback: %s", e)
        result["errors"].append(f"Full DEX analysis failed: {e}")
        try:
            from androguard.core.apk import APK
            a = APK(apk_path)
            if not _safe(a.is_valid_APK, False):
                raise ValueError("AndroidManifest.xml is missing or invalid")
            dex_list, dx = [], None
            analysis_quality = "partial"
        except Exception as fallback_error:
            # Neither manifest nor bytecode is usable: this is Unknown, not Low.
            log.warning("Manifest fallback failed: %s", fallback_error)
            result["errors"].append(f"APK manifest parsing failed: {fallback_error}")
            result["manifest"] = {}
            result["certificate"] = {"present": False, "flags": [], "score": 0}
            result["components"] = {"exported": [], "count": 0, "score": 0}
            result["permissions"] = {"all_permissions": [], "dangerous": [], "dangerous_count": 0}
            result["apis"] = {"suspicious_apis": [], "count": 0}
            result["iocs"] = iocs.extract_iocs([])
            result["obfuscation"] = {"signals": [], "score": 0, "is_obfuscated": False}
            result["yara"] = {"available": yara_scan.available(), "matches": [], "score": 0}
            result["apkid"] = {"available": apkid_scan.available(), "findings": [], "score": 0}
            result["mitre"] = {"techniques": [], "tactics": [], "count": 0}
            result["ml"] = {"available": False}
            result["risk_score"] = None
            result["severity"] = "Unknown"
            result["score_breakdown"] = []
            result["detected_behaviors"] = []
            result["recommendations"] = ["Analysis could not complete — re-check the file is a valid APK."]
            result["valid_apk"] = False
            result["analysis_quality"] = "failed"
            return result

    result["valid_apk"] = True
    result["analysis_quality"] = analysis_quality

    # --- Manifest metadata ---
    manifest = {
        "package_name": _safe(a.get_package, ""),
        "app_name": _safe(a.get_app_name, ""),
        "version_name": _safe(a.get_androidversion_name, ""),
        "version_code": _safe(a.get_androidversion_code, ""),
        "min_sdk": _safe(a.get_min_sdk_version, ""),
        "target_sdk": _safe(a.get_target_sdk_version, ""),
        "main_activity": _safe(a.get_main_activity, ""),
        "activities": _safe(a.get_activities, []),
        "services": _safe(a.get_services, []),
        "receivers": _safe(a.get_receivers, []),
        "providers": _safe(a.get_providers, []),
    }
    manifest["counts"] = {
        "activities": len(manifest["activities"]),
        "services": len(manifest["services"]),
        "receivers": len(manifest["receivers"]),
        "providers": len(manifest["providers"]),
    }
    result["manifest"] = manifest

    # --- Certificate / signature red-flags ---
    cert_result = cert_analysis.analyze_certificate(a)
    result["certificate"] = cert_result

    # --- Exported components (attack surface) ---
    comp_result = components.analyze_components(a)
    result["components"] = comp_result

    # --- Permissions ---
    perms = _safe(a.get_permissions, [])
    perm_result = permissions.analyze_permissions(perms)
    result["permissions"] = perm_result

    # --- DEX strings (shared by API, IOC, obfuscation stages) ---
    dex_strings = (_collect_dex_strings(dex_list, dx) if analysis_quality == "full"
                   else _collect_raw_dex_strings(a))
    result["analysis_coverage"] = {
        "manifest": True,
        "dex_control_flow": analysis_quality == "full",
        "dex_strings": len(dex_strings),
    }
    native_strings = _collect_native_strings(a)
    # IOC + YARA scan over DEX *and* native-lib strings; API detection stays on DEX.
    text_strings = dex_strings + native_strings

    # --- Suspicious APIs ---
    api_result = api_patterns.analyze_apis(dx, dex_strings)
    result["apis"] = api_result

    # --- IOCs (DEX + native strings + Base64/hex decode) ---
    ioc_result = iocs.extract_iocs(text_strings)
    ioc_result["native_strings_scanned"] = len(native_strings)
    result["iocs"] = ioc_result

    # --- Obfuscation ---
    obf_result = obfuscation.analyze_obfuscation(a, dex_list, dex_strings, api_result)
    result["obfuscation"] = obf_result

    # --- YARA signatures ---
    yara_result = yara_scan.scan(text_strings, perms, manifest.get("package_name", ""))
    result["yara"] = yara_result

    # --- APKiD fingerprinting (packer / repackaging / anti-analysis) ---
    apkid_result = apkid_scan.scan(apk_path)
    result["apkid"] = apkid_result

    # --- Risk scoring + behaviours + recommendations ---
    risk = risk_scoring.compute_risk(perm_result, api_result, ioc_result, obf_result,
                                     yara_result, apkid_result, cert_result, comp_result,
                                     manifest)
    result.update(risk)
    behaviors = risk_scoring.derive_behaviors(perm_result, api_result, ioc_result, obf_result)
    result["detected_behaviors"] = behaviors
    result["recommendations"] = risk_scoring.recommendations(risk["severity"], behaviors, ioc_result)

    # --- MITRE ATT&CK (Mobile) mapping ---
    result["mitre"] = mitre.map_attack(perm_result, api_result, behaviors, obf_result)

    # --- ML classifier (optional; hybrid score per plan §7) ---
    ml_result = ml_classifier.predict(result)
    risk_scoring.apply_ml(result, ml_result)
    # Recompute recommendations against the (possibly ML-adjusted) severity.
    result["recommendations"] = risk_scoring.recommendations(
        result["severity"], behaviors, ioc_result)
    if analysis_quality == "partial":
        result["recommendations"].append(
            "DEX control-flow analysis was incomplete; manually review with another "
            "decompiler and use isolated dynamic analysis before clearing this sample."
        )

    return result
