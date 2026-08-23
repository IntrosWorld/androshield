"""VirusTotal threat-intel corroboration.

Looks up the APK's SHA256 (and a few extracted domains/IPs) against the free
VirusTotal API v3 to corroborate the local heuristic verdict with real multi-engine
detections. Entirely optional: with no VT_API_KEY it returns {"configured": False}
and the rest of the pipeline is unaffected.

Free tier limits: 4 requests/min, 500/day — so we query the file hash first (most
valuable) and cap domain/IP lookups, backing off on HTTP 429.
"""
import logging
import os
import time

log = logging.getLogger("virustotal")

VT_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 15
MAX_DOMAIN_LOOKUPS = 3   # keep total requests within the 4/min free tier


def is_configured() -> bool:
    enabled = os.getenv("EXTERNAL_API_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
    return enabled and bool(os.getenv("VT_API_KEY", "").strip())


def _headers():
    return {"x-apikey": os.getenv("VT_API_KEY", "").strip(),
            "accept": "application/json"}


def _stats(attributes):
    s = (attributes or {}).get("last_analysis_stats", {}) or {}
    return {
        "malicious": s.get("malicious", 0),
        "suspicious": s.get("suspicious", 0),
        "harmless": s.get("harmless", 0),
        "undetected": s.get("undetected", 0),
        "total_engines": sum(v for v in s.values() if isinstance(v, int)),
    }


def _lookup_file(session, sha256):
    try:
        r = session.get(f"{VT_BASE}/files/{sha256}", headers=_headers(), timeout=TIMEOUT)
    except Exception as e:
        return {"found": False, "error": f"request failed: {e}"}, False

    if r.status_code == 404:
        return {"found": False, "note": "Not previously seen on VirusTotal"}, False
    if r.status_code == 429:
        return {"found": False, "error": "VirusTotal rate limit reached"}, True
    if r.status_code in (401, 403):
        return {"found": False, "error": "Invalid or unauthorized VT_API_KEY"}, True
    if r.status_code != 200:
        return {"found": False, "error": f"VT HTTP {r.status_code}"}, False

    attrs = (r.json().get("data") or {}).get("attributes", {}) or {}
    stats = _stats(attrs)
    # Top engine detections (named verdicts).
    hits = []
    for engine, res in (attrs.get("last_analysis_results", {}) or {}).items():
        if res.get("category") in ("malicious", "suspicious") and res.get("result"):
            hits.append({"engine": engine, "result": res["result"]})
    hits.sort(key=lambda h: h["engine"].lower())
    label = (attrs.get("popular_threat_classification", {}) or {}).get("suggested_threat_label")
    return {
        "found": True,
        **stats,
        "threat_label": label or "",
        "engine_hits": hits[:25],
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }, False


def _lookup_domain(session, domain):
    try:
        r = session.get(f"{VT_BASE}/domains/{domain}", headers=_headers(), timeout=TIMEOUT)
        if r.status_code == 429:
            return None, True
        if r.status_code != 200:
            return None, False
        attrs = (r.json().get("data") or {}).get("attributes", {}) or {}
        s = _stats(attrs)
        return {"domain": domain, "malicious": s["malicious"], "suspicious": s["suspicious"]}, False
    except Exception:
        return None, False


def lookup(sha256: str, domains=None, ips=None) -> dict:
    """Return VirusTotal corroboration for a sample. Never raises."""
    if not is_configured():
        return {"configured": False, "queried": False}

    result = {"configured": True, "queried": True}
    try:
        import requests
        session = requests.Session()

        file_res, rate_limited = _lookup_file(session, sha256)
        result["file"] = file_res

        # Domain reputation (bounded; skip if we already hit the rate limit).
        flagged_domains = []
        if not rate_limited:
            for d in (domains or [])[:MAX_DOMAIN_LOOKUPS]:
                dres, rl = _lookup_domain(session, d)
                if dres and (dres["malicious"] or dres["suspicious"]):
                    flagged_domains.append(dres)
                if rl:
                    break
                time.sleep(1)  # be gentle on the free tier
        result["flagged_domains"] = flagged_domains
        return result
    except Exception as e:
        log.exception("VirusTotal lookup failed")
        return {"configured": True, "queried": True, "error": str(e)}
