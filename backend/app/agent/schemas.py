"""Strict validation for model-selected actions and final hypotheses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


POLICY_VERSION = "agent-policy-v1"
MAX_CLAIMS = 10
MAX_LIST_ITEMS = 12


class AgentSchemaError(ValueError):
    pass


def _text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentSchemaError(f"{field} must be a non-empty string")
    return value.strip()[:limit]


@dataclass(frozen=True)
class ToolDecision:
    tool: str
    arguments: dict[str, Any]
    reason: str


@dataclass(frozen=True)
class FinalDecision:
    hypotheses: list[dict[str, Any]]
    gaps: list[str]
    recommended_next_steps: list[str]


def validate_tool_decision(value: Any) -> ToolDecision:
    if not isinstance(value, dict) or value.get("type") != "tool":
        raise AgentSchemaError("expected a tool decision")
    allowed = {"type", "tool", "arguments", "reason"}
    unknown = set(value) - allowed
    if unknown:
        raise AgentSchemaError(f"unknown tool-decision fields: {sorted(unknown)}")
    tool = _text(value.get("tool"), "tool", 80)
    arguments = value.get("arguments", {})
    if not isinstance(arguments, dict):
        raise AgentSchemaError("arguments must be an object")
    reason = _text(value.get("reason", "Evidence needed for investigation"), "reason", 500)
    return ToolDecision(tool=tool, arguments=arguments, reason=reason)


def validate_final_decision(value: Any, valid_evidence_ids: set[str]) -> FinalDecision:
    if not isinstance(value, dict) or value.get("type") != "final":
        raise AgentSchemaError("expected a final decision")
    allowed = {"type", "hypotheses", "gaps", "recommended_next_steps"}
    unknown = set(value) - allowed
    if unknown:
        raise AgentSchemaError(f"unknown final-decision fields: {sorted(unknown)}")

    raw_hypotheses = value.get("hypotheses", [])
    if not isinstance(raw_hypotheses, list) or len(raw_hypotheses) > MAX_CLAIMS:
        raise AgentSchemaError(f"hypotheses must be a list of at most {MAX_CLAIMS}")
    hypotheses = []
    for index, item in enumerate(raw_hypotheses):
        if not isinstance(item, dict) or set(item) - {"claim", "confidence", "evidence_ids"}:
            raise AgentSchemaError(f"hypotheses[{index}] has an invalid shape")
        claim = _text(item.get("claim"), f"hypotheses[{index}].claim", 1000)
        confidence = item.get("confidence")
        if confidence not in {"low", "medium", "high"}:
            raise AgentSchemaError(f"hypotheses[{index}].confidence is invalid")
        evidence_ids = item.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids or len(evidence_ids) > 20:
            raise AgentSchemaError(f"hypotheses[{index}] must cite evidence")
        evidence_ids = list(dict.fromkeys(str(x) for x in evidence_ids))
        missing = [item_id for item_id in evidence_ids if item_id not in valid_evidence_ids]
        if missing:
            raise AgentSchemaError(f"hypotheses[{index}] cites unknown evidence: {missing[:3]}")
        hypotheses.append({
            "claim": claim,
            "confidence": confidence,
            "evidence_ids": evidence_ids,
        })

    def clean_list(field: str) -> list[str]:
        raw = value.get(field, [])
        if not isinstance(raw, list) or len(raw) > MAX_LIST_ITEMS:
            raise AgentSchemaError(f"{field} must be a list of at most {MAX_LIST_ITEMS}")
        return [_text(item, field, 500) for item in raw]

    gaps = clean_list("gaps")
    next_steps = clean_list("recommended_next_steps")
    if not hypotheses and not gaps:
        raise AgentSchemaError("a final decision needs a hypothesis or an evidence gap")
    return FinalDecision(hypotheses, gaps, next_steps)
