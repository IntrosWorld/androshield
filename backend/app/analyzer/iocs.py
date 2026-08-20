"""Indicator-of-Compromise extraction from DEX strings.

Pulls URLs, domains, IP addresses, suspicious keywords, Telegram bot tokens,
Firebase endpoints and likely hardcoded secrets out of the decompiled strings.
Also auto-decodes Base64/hex blobs and re-scans the decoded text — a common way
malware hides C2 URLs and keywords from a naive string scan.
"""
import base64
import ipaddress
import re
from urllib.parse import urlsplit

_B64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){8,}$")


def _printable_ratio(t):
    if not t:
        return 0.0
    return sum(c.isprintable() or c in "\t\n" for c in t) / len(t)


def _decode_candidates(strings, cap=400):
    """Yield decoded printable text from Base64/hex-looking strings."""
    out = []
    for s in strings or []:
        t = (s or "").strip()
        if not (16 <= len(t) <= 2048):
            continue
        decoded = None
        try:
            if _B64_RE.match(t) and len(t) % 4 == 0:
                decoded = base64.b64decode(t, validate=True).decode("utf-8", "ignore")
            elif _HEX_RE.match(t):
                decoded = bytes.fromhex(t).decode("utf-8", "ignore")
        except Exception:
            decoded = None
        if decoded and len(decoded) >= 4 and _printable_ratio(decoded) > 0.85:
            out.append(decoded)
        if len(out) >= cap:
            break
    return out

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|xyz|top|info|ru|cn|tk|ml|ga|cf|gq|online|site|club|live|icu|vip|cc|io|app|shop|fun)\b",
    re.IGNORECASE,
)
TELEGRAM_TOKEN_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")
FIREBASE_RE = re.compile(r"https://[a-z0-9-]+\.firebaseio\.com", re.IGNORECASE)
SECRET_RE = re.compile(r"(?:api[_-]?key|secret|token|password|passwd|bearer)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{12,})",
                       re.IGNORECASE)

# Keywords that, when hardcoded, suggest banking/credential targeting.
SUSPICIOUS_KEYWORDS = [
    "otp", "cvv", "pin", "ifsc", "upi", "aadhaar", "netbanking", "debit",
    "credit card", "card number", "account number", "mpin", "passcode",
    "username", "password", "login", "phishing", "keylog", "overlay",
    "telegram", "bot", "c2", "command", "exfil", "screenshot",
]

# High-signal subset actually used for *scoring*. Generic words like "login" /
# "password" / "username" appear in almost every app (and in translation strings),
# so they're reported but NOT scored — only specific financial-fraud terms count.
FINANCIAL_KEYWORDS = {
    "otp", "cvv", "ifsc", "upi", "aadhaar", "netbanking", "mpin",
    "debit", "credit card", "card number", "account number", "passcode",
}

# Precompiled word-boundary matchers for each keyword.
_KEYWORD_RE = {kw: re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE)
               for kw in SUSPICIOUS_KEYWORDS}

# Domains we don't want to flag as IOCs (common SDK / platform infra).
BENIGN_DOMAIN_SUFFIXES = (
    "schemas.android.com", "w3.org", "apache.org", "google.com",
    "googleapis.com", "gstatic.com", "android.com", "github.com",
    "json.org", "slf4j.org", "bouncycastle.org",
)

# TLDs are not malicious by themselves, but these low-cost/abuse-heavy namespaces are
# useful weak evidence when combined with fraud paths or other capabilities. This list
# intentionally affects only explainable URL triage; it never produces a verdict alone.
HIGHER_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "vip", "cc", "fun",
}
_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|[/_.-])(login|signin|verify|bank|otp|upload|exfil|gate|panel|c2|beacon)(?:[/_.-]|$)",
    re.IGNORECASE,
)


def _is_benign_domain(d: str) -> bool:
    dl = d.lower()
    # Require a DNS label boundary. A raw suffix check would incorrectly trust attacker
    # domains such as ``notgoogle.com`` because they end with ``google.com``.
    return any(dl == s or dl.endswith("." + s) for s in BENIGN_DOMAIN_SUFFIXES)


def _url_risk(url: str):
    """Return weak, transparent risk reasons for a statically embedded URL."""
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
    except (TypeError, ValueError):
        return []
    if not host or _is_benign_domain(host):
        return []

    reasons = []
    try:
        address = ipaddress.ip_address(host)
        reasons.append("private/local IP host" if address.is_private or address.is_loopback
                       else "literal IP host")
    except ValueError:
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in HIGHER_RISK_TLDS:
            reasons.append(f"higher-risk .{tld} domain")
        if host.startswith("xn--") or ".xn--" in host:
            reasons.append("internationalized/punycode domain")

    path = parsed.path or ""
    if _SENSITIVE_PATH_RE.search(path):
        reasons.append("fraud/C2-like path")
    try:
        if parsed.port and parsed.port not in (80, 443):
            reasons.append(f"non-standard port {parsed.port}")
    except ValueError:
        reasons.append("malformed port")
    if parsed.username or parsed.password:
        reasons.append("credentials embedded in URL")
    if parsed.scheme.lower() == "http" and len(reasons) > 0:
        reasons.append("cleartext HTTP")
    return reasons


def extract_iocs(dex_strings, max_each: int = 200):
    urls, ips, domains, keywords = set(), set(), set(), {}
    telegram, firebase, secrets = set(), set(), set()

    # Decode Base64/hex blobs and scan them alongside the raw strings.
    decoded = _decode_candidates(dex_strings)
    scan_strings = list(dex_strings or []) + decoded

    for s in scan_strings:
        if not s or len(s) > 4000:
            continue

        for m in URL_RE.findall(s):
            urls.add(m.rstrip(".,);"))
        for m in IP_RE.findall(s):
            # skip obvious version-number / loopback noise
            if m.startswith(("0.", "127.", "255.")) or m == "0.0.0.0":
                continue
            ips.add(m)
        for m in FIREBASE_RE.findall(s):
            firebase.add(m)
        for m in TELEGRAM_TOKEN_RE.findall(s):
            telegram.add(m)
        for m in SECRET_RE.findall(s):
            secrets.add(m)

        low = s.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            # Word-boundary match — substring matching produced false positives like
            # "upi" inside "grouping"/"occupied" or "otp" inside "crypto".
            if _KEYWORD_RE[kw].search(low):
                keywords[kw] = keywords.get(kw, 0) + 1

    # Domains are derived ONLY from real URLs. A bare-string domain scan was matching
    # Java package names (android.app, kotlinx.coroutines.io, libcore.icu.icu — ".io"/
    # ".app"/".icu"/".cc" are valid TLDs) and flooding benign apps with fake IOCs.
    for u in urls:
        host = re.sub(r"^https?://", "", u, flags=re.IGNORECASE).split("/")[0].split(":")[0]
        if host and not IP_RE.fullmatch(host) and not _is_benign_domain(host):
            domains.add(host.lower())

    suspicious_urls = []
    for url in sorted(urls):
        reasons = _url_risk(url)
        if reasons:
            stronger = (
                "literal IP host", "internationalized/punycode domain",
                "credentials embedded in URL",
            )
            confidence = "medium" if (
                any(r in stronger for r in reasons)
                or any(r.startswith("higher-risk .") for r in reasons)
            ) else "low"
            # Multiple independent properties increase confidence, but a URL remains
            # weak evidence and is capped well below a behavioral detector.
            suspicious_urls.append({
                "url": url,
                "reasons": reasons,
                "score": min(2 + max(0, len(reasons) - 1), 5),
                "confidence": confidence,
            })

    def cap(it):
        return sorted(it)[:max_each]

    return {
        "urls": cap(urls),
        "suspicious_urls": suspicious_urls[:max_each],
        "ips": cap(ips),
        "domains": cap(domains),
        "firebase_endpoints": cap(firebase),
        "telegram_tokens": cap(telegram),
        "hardcoded_secrets": cap(secrets),
        "suspicious_keywords": sorted(
            ({"keyword": k, "count": v} for k, v in keywords.items()),
            key=lambda x: x["count"], reverse=True,
        ),
        "financial_keywords": sorted(k for k in keywords if k in FINANCIAL_KEYWORDS),
        "decoded_blobs": len(decoded),
        "counts": {
            "urls": len(urls), "ips": len(ips), "domains": len(domains),
            "suspicious_urls": len(suspicious_urls),
            "telegram_tokens": len(telegram), "secrets": len(secrets),
            "keywords": len(keywords),
            "financial_keywords": sum(1 for k in keywords if k in FINANCIAL_KEYWORDS),
            "decoded_blobs": len(decoded),
        },
    }
