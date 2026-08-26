"""Convert live analyzer output into the rich CIC training feature dictionary.

The Kaggle model was trained with these same locally extracted fields and a
``DictVectorizer``. Keeping the mapping here makes inference schema explicit and
prevents accidental feature-order drift.
"""

from .features import short_perm


def _number(value, default=0.0):
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _sum_score(items):
    return sum(_number(item.get("score")) for item in (items or []) if isinstance(item, dict))


def _add_categories(row, prefix, values):
    for value in values or []:
        value = str(value).strip()
        if value:
            row[f"{prefix}={value}"] = 1.0


def from_analysis(analysis: dict) -> dict:
    """Return exactly the evidence feature space used by ``apk_static_model``."""
    analysis = analysis or {}
    manifest = analysis.get("manifest") or {}
    counts = manifest.get("counts") or {}
    permissions = analysis.get("permissions") or {}
    dangerous = permissions.get("dangerous") or []
    apis = analysis.get("apis") or {}
    api_findings = apis.get("suspicious_apis") or []
    iocs = analysis.get("iocs") or {}
    ioc_counts = iocs.get("counts") or {}
    obfuscation = analysis.get("obfuscation") or {}
    obf_signals = obfuscation.get("signals") or []
    yara = analysis.get("yara") or {}
    yara_matches = yara.get("matches") or []
    apkid = analysis.get("apkid") or {}
    apkid_findings = apkid.get("findings") or []
    certificate = analysis.get("certificate") or {}
    cert_flags = certificate.get("flags") or []
    components = analysis.get("components") or {}
    coverage = analysis.get("analysis_coverage") or {}

    row = {
        "package_present": float(bool(manifest.get("package_name"))),
        "min_sdk": _number(manifest.get("min_sdk")),
        "target_sdk": _number(manifest.get("target_sdk")),
        "activities": _number(counts.get("activities", len(manifest.get("activities") or []))),
        "services": _number(counts.get("services", len(manifest.get("services") or []))),
        "receivers": _number(counts.get("receivers", len(manifest.get("receivers") or []))),
        "providers": _number(counts.get("providers", len(manifest.get("providers") or []))),
        "permission_count": _number(len(permissions.get("all_permissions") or [])),
        "dangerous_permission_count": _number(permissions.get("dangerous_count", len(dangerous))),
        "dangerous_permission_raw_points": _sum_score(dangerous),
        "api_count": _number(apis.get("count", len(api_findings))),
        "api_scoreable_count": _number(sum(_number(item.get("score")) > 0 for item in api_findings)),
        "api_raw_points": _sum_score(api_findings),
        "url_count": _number(ioc_counts.get("urls", len(iocs.get("urls") or []))),
        "suspicious_url_count": _number(ioc_counts.get("suspicious_urls", len(iocs.get("suspicious_urls") or []))),
        "ip_count": _number(ioc_counts.get("ips", len(iocs.get("ips") or []))),
        "domain_count": _number(ioc_counts.get("domains", len(iocs.get("domains") or []))),
        "keyword_count": _number(ioc_counts.get("keywords", len(iocs.get("suspicious_keywords") or []))),
        "financial_keyword_count": _number(ioc_counts.get("financial_keywords", len(iocs.get("financial_keywords") or []))),
        "decoded_blob_count": _number(ioc_counts.get("decoded_blobs", iocs.get("decoded_blobs", 0))),
        "obfuscation_signal_count": _number(len(obf_signals)),
        "obfuscation_raw_points": _sum_score(obf_signals),
        "yara_match_count": _number(yara.get("count", len(yara_matches))),
        "yara_raw_points": _sum_score(yara_matches),
        "apkid_finding_count": _number(apkid.get("count", len(apkid_findings))),
        "apkid_raw_points": _sum_score(apkid_findings),
        "certificate_present": float(bool(certificate.get("present"))),
        "certificate_flag_count": _number(len(cert_flags)),
        "certificate_validity_years": _number(certificate.get("validity_years")),
        "certificate_self_signed": float(bool(certificate.get("self_signed"))),
        "exported_component_count": _number(components.get("count", len(components.get("exported") or []))),
        "unguarded_exported_count": _number(components.get("unguarded_count")),
        "dex_string_count": _number(coverage.get("dex_strings")),
        "dex_control_flow": float(bool(coverage.get("dex_control_flow"))),
        "native_string_count": _number(iocs.get("native_strings_scanned")),
    }

    all_permissions = {short_perm(p) for p in permissions.get("all_permissions") or []}
    _add_categories(row, "perm", sorted(all_permissions))
    _add_categories(row, "dangerous_perm", [item.get("name") for item in dangerous])
    _add_categories(row, "api", [item.get("api") for item in api_findings])
    _add_categories(row, "yara", [item.get("rule") for item in yara_matches])
    _add_categories(row, "obfuscation", [item.get("signal") for item in obf_signals])
    _add_categories(row, "certificate_flag", [item.get("flag") for item in cert_flags])
    _add_categories(row, "apkid", [item.get("category") for item in apkid_findings])
    _add_categories(row, "financial_keyword", iocs.get("financial_keywords") or [])
    return row
