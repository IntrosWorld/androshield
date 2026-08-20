"""Create a compact immutable evidence graph from static-analysis findings."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any


_ID_SAFE = re.compile(r"[^A-Za-z0-9_.:-]+")


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "[depth limit]"
    if isinstance(value, str):
        return value[:1000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, list):
        return [_bounded(item, depth + 1) for item in value[:50]]
    if isinstance(value, dict):
        return {str(k)[:100]: _bounded(v, depth + 1) for k, v in list(value.items())[:100]}
    return str(value)[:1000]


def _slug(value: Any, fallback: str) -> str:
    text = _ID_SAFE.sub("_", str(value or fallback)).strip("_")
    return text[:100] or fallback


def build_evidence(analysis: dict) -> dict:
    """Return model-safe extracted evidence; never include a path or raw APK bytes."""
    source = deepcopy(analysis)
    items: list[dict] = []
    used: set[str] = set()

    def add(kind: str, key: Any, summary: str, data: Any):
        base = f"{kind}:{_slug(key, str(len(items) + 1))}"
        item_id = base
        suffix = 2
        while item_id in used:
            item_id = f"{base}:{suffix}"
            suffix += 1
        used.add(item_id)
        items.append({
            "id": item_id,
            "kind": kind,
            "summary": str(summary)[:500],
            "data": _bounded(data),
        })

    manifest = source.get("manifest", {}) or {}
    manifest_view = {
        key: manifest.get(key)
        for key in (
            "package_name", "app_name", "version_name", "version_code", "min_sdk",
            "target_sdk", "main_activity", "debuggable", "allow_backup",
            "activities", "services", "receivers", "providers",
        )
        if key in manifest
    }
    add("manifest", "summary", "Extracted Android manifest metadata", manifest_view)

    for permission in (source.get("permissions", {}) or {}).get("dangerous", []) or []:
        add("permission", permission.get("name"), permission.get("reason", "Dangerous permission"), permission)
    for api in (source.get("apis", {}) or {}).get("suspicious_apis", []) or []:
        add("api", api.get("api"), api.get("behaviour", "Suspicious API evidence"), api)

    iocs = source.get("iocs", {}) or {}
    for field in ("urls", "domains", "ips", "telegram_tokens", "firebase_endpoints"):
        for value in iocs.get(field, []) or []:
            add("ioc", f"{field}-{value}", f"Extracted {field[:-1] if field.endswith('s') else field}", {
                "type": field, "value": value,
            })
    for keyword in iocs.get("suspicious_keywords", []) or []:
        add("keyword", keyword.get("keyword"), "Suspicious keyword found in extracted strings", keyword)

    for match in (source.get("yara", {}) or {}).get("matches", []) or []:
        add("yara", match.get("rule"), match.get("description", "YARA match"), match)
    for finding in (source.get("apkid", {}) or {}).get("findings", []) or []:
        add("apkid", finding.get("name"), "APKiD fingerprint", finding)
    for technique in (source.get("mitre", {}) or {}).get("techniques", []) or []:
        add("mitre", technique.get("id"), technique.get("name", "ATT&CK technique"), technique)
    for flag in (source.get("certificate", {}) or {}).get("flags", []) or []:
        add("certificate", flag.get("flag"), "Certificate red flag", flag)

    components = source.get("components", {}) or {}
    if components:
        add("component", "attack_surface", "Exported-component attack surface", components)
    for score_item in source.get("score_breakdown", []) or []:
        add("score", score_item.get("category"), score_item.get("detail", "Risk contribution"), score_item)

    index: dict[str, int] = {}
    for item in items:
        index[item["kind"]] = index.get(item["kind"], 0) + 1
    return {
        "case": {
            "package_name": manifest.get("package_name"),
            "analysis_quality": source.get("analysis_quality", "full"),
            "risk_score": source.get("risk_score"),
            "severity": source.get("severity"),
            "detected_behaviors": _bounded(source.get("detected_behaviors", [])),
        },
        "index": index,
        "items": items,
        "evidence_ids": used,
    }


def public_evidence_index(graph: dict) -> dict:
    """Small first-turn view; details require an explicit read-only tool action."""
    return {
        "case": graph["case"],
        "counts_by_kind": graph["index"],
        "evidence_id_count": len(graph["items"]),
        "sample_evidence_ids": [item["id"] for item in graph["items"][:200]],
    }


def evidence_json(value: Any) -> str:
    return json.dumps(_bounded(value), ensure_ascii=False, separators=(",", ":"))
