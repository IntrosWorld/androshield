"""Allowlisted tools over a server-bound, extracted-evidence graph."""

from __future__ import annotations

import json
from typing import Any

from .schemas import AgentSchemaError


READ_TOOLS = {
    "inspect_manifest": {"manifest"},
    "inspect_permissions": {"permission"},
    "inspect_apis": {"api"},
    "inspect_network": {"ioc", "keyword"},
    "inspect_signatures": {"yara", "apkid", "mitre", "certificate"},
    "inspect_score_rationale": {"score"},
    "inspect_attack_surface": {"component"},
}
APPROVAL_TOOLS = {"request_dynamic_analysis", "request_external_intel"}


def tool_specs(include_approval_tools: bool = True) -> list[dict]:
    descriptions = {
        "inspect_manifest": "Read extracted Android manifest metadata for the server-bound current case.",
        "inspect_permissions": "Read dangerous permission evidence for the current case.",
        "inspect_apis": "Read suspicious API evidence for the current case.",
        "inspect_network": "Read extracted network indicators and suspicious keywords for the current case.",
        "inspect_signatures": "Read YARA, APKiD, certificate, and MITRE evidence for the current case.",
        "inspect_score_rationale": "Read the deterministic score breakdown. The tool cannot change the score.",
        "inspect_attack_surface": "Read exported-component attack-surface evidence.",
        "search_evidence": "Case-insensitive substring search over already-extracted evidence.",
    }
    specs = []
    for name, description in descriptions.items():
        properties = {}
        required = []
        if name == "search_evidence":
            properties = {"query": {"type": "string", "minLength": 1, "maxLength": 100}}
            required = ["query"]
        specs.append({
            "type": "function",
            "function": {
                "name": name,
                "description": description + " It is read-only and never executes the APK.",
                "parameters": {
                    "type": "object", "properties": properties,
                    "required": required, "additionalProperties": False,
                },
            },
        })
    if include_approval_tools:
        for name, description in {
            "request_dynamic_analysis": "Propose isolated-emulator dynamic analysis; never starts it.",
            "request_external_intel": "Propose an external intelligence query; never sends data.",
        }.items():
            specs.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": description + " Returns approval_required.",
                    "parameters": {
                        "type": "object",
                        "properties": {"reason": {"type": "string", "maxLength": 500}},
                        "required": ["reason"], "additionalProperties": False,
                    },
                },
            })
    return specs


class EvidenceToolbox:
    def __init__(self, graph: dict):
        self.graph = graph

    def execute(self, name: str, arguments: dict[str, Any]) -> dict:
        if not isinstance(arguments, dict):
            raise AgentSchemaError("tool arguments must be an object")
        if name in READ_TOOLS:
            if arguments:
                raise AgentSchemaError(f"{name} accepts no arguments")
            kinds = READ_TOOLS[name]
            return self._result([item for item in self.graph["items"] if item["kind"] in kinds])
        if name == "search_evidence":
            if set(arguments) != {"query"}:
                raise AgentSchemaError("search_evidence requires only query")
            query = arguments.get("query")
            if not isinstance(query, str) or not query.strip() or len(query) > 100:
                raise AgentSchemaError("query must be 1-100 characters")
            needle = query.casefold()
            matches = []
            for item in self.graph["items"]:
                haystack = json.dumps(item, ensure_ascii=False).casefold()
                if needle in haystack:
                    matches.append(item)
            return self._result(matches[:20])
        if name in APPROVAL_TOOLS:
            if set(arguments) != {"reason"}:
                raise AgentSchemaError(f"{name} requires only reason")
            reason = arguments.get("reason")
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
                raise AgentSchemaError("approval reason must be 1-500 characters")
            return {
                "status": "approval_required",
                "action": name,
                "reason": reason.strip(),
                "executed": False,
                "evidence_ids": [],
            }
        raise AgentSchemaError(f"tool is not allowlisted: {name}")

    @staticmethod
    def _result(items: list[dict]) -> dict:
        selected = []
        characters = 0
        for item in items[:20]:
            size = len(json.dumps(item, ensure_ascii=False))
            if selected and characters + size > 12000:
                break
            if not selected and size > 12000:
                item = {
                    "id": item["id"], "kind": item["kind"],
                    "summary": item["summary"],
                    "data": str(item.get("data", ""))[:8000] + " [truncated]",
                }
                size = len(json.dumps(item, ensure_ascii=False))
            selected.append(item)
            characters += size
        return {
            "status": "ok",
            "items": selected,
            "evidence_ids": [item["id"] for item in selected],
            "truncated": len(selected) < len(items),
        }
