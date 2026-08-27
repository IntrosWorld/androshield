"""Approval-controlled closed-loop investigation workflow.

This module is deliberately additive: the existing evidence agent and manual dynamic
endpoint keep their behavior.  A workflow proposes one fixed, allowlisted sandbox
action at a time, records explicit approval, and feeds bounded observations back to the
evidence agent.  It never receives an APK path and never executes anything itself.
"""

from __future__ import annotations

import os
import time
import uuid
from copy import deepcopy


WORKFLOW_POLICY_VERSION = "agent-workflow-v1"
ACTION_CONFIGS = {
    "dynamic_baseline": {
        "title": "Baseline sandbox observation",
        "duration": 20,
        "use_frida": False,
        "use_ui_agent": False,
        "ui_agent_mode": "tree",
    },
    "dynamic_frida": {
        "title": "Frida runtime instrumentation",
        "duration": 30,
        "use_frida": True,
        "use_ui_agent": False,
        "ui_agent_mode": "tree",
    },
    "dynamic_ui_tree": {
        "title": "Bounded UI-tree exploration",
        "duration": 30,
        "use_frida": False,
        "use_ui_agent": True,
        "ui_agent_mode": "tree",
    },
    "dynamic_ui_vision": {
        "title": "Bounded vision-assisted exploration",
        "duration": 30,
        "use_frida": False,
        "use_ui_agent": True,
        "ui_agent_mode": "vision",
    },
}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def health() -> dict:
    return {
        "enabled": _env_bool("AGENT_WORKFLOW_ENABLED", False),
        "policy_version": WORKFLOW_POLICY_VERSION,
        "approval_required": True,
        "allowed_actions": list(ACTION_CONFIGS),
    }


def _evidence_ids(investigation: dict) -> list[str]:
    ids = []
    for hypothesis in (investigation or {}).get("hypotheses", []) or []:
        ids.extend(str(item) for item in hypothesis.get("evidence_ids", []) or [])
    return list(dict.fromkeys(ids))[:20]


def _proposal(kind: str, reason: str, investigation: dict) -> dict:
    config = ACTION_CONFIGS[kind]
    return {
        "id": "action-" + uuid.uuid4().hex[:10],
        "kind": kind,
        "title": config["title"],
        "reason": reason[:500],
        "evidence_ids": _evidence_ids(investigation),
        "config": {
            "duration": config["duration"],
            "use_frida": config["use_frida"],
            "use_ui_agent": config["use_ui_agent"],
            "ui_agent_mode": config["ui_agent_mode"],
        },
        "requires_approval": True,
        "status": "pending",
        "created_at": time.time(),
    }


def _static_capabilities(analysis: dict) -> dict:
    perms = {p.get("name") for p in (analysis.get("permissions") or {}).get("dangerous", [])}
    apis = {a.get("api") for a in (analysis.get("apis") or {}).get("suspicious_apis", [])}
    apkid = {f.get("category") for f in (analysis.get("apkid") or {}).get("findings", [])}
    obfuscation = analysis.get("obfuscation") or {}
    manifest = analysis.get("manifest") or {}
    return {
        "packed_or_dynamic": bool(
            apis & {"DexClassLoader", "PathClassLoader"}
            or apkid & {"Packer", "Protector", "Dropper"}
            or obfuscation.get("score", 0) >= 8
        ),
        "ui_relevant": bool(
            manifest.get("main_activity")
            and (perms & {"SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "READ_SMS", "RECEIVE_SMS"}
                 or apis & {"AccessibilityService", "WebView.addJavascriptInterface"})
        ),
        "has_launcher": bool(manifest.get("main_activity")),
    }


def start(analysis: dict, investigation: dict, *, allow_vision: bool = False) -> dict:
    """Create a workflow without changing the existing agent result or score."""
    proposal = _proposal(
        "dynamic_baseline",
        "Collect a minimal isolated runtime baseline before choosing invasive instrumentation.",
        investigation,
    )
    return {
        "enabled": True,
        "id": "workflow-" + uuid.uuid4().hex[:10],
        "status": "approval_required",
        "policy_version": WORKFLOW_POLICY_VERSION,
        "created_at": time.time(),
        "static_score_snapshot": analysis.get("risk_score"),
        "static_severity_snapshot": analysis.get("severity"),
        "allow_vision": bool(allow_vision),
        "agent_reviews": [deepcopy(investigation)],
        "proposals": [proposal],
        "observations": [],
        "audit": [{
            "step": 1,
            "event": "workflow_started",
            "status": "completed",
            "action_id": proposal["id"],
            "detail": "Baseline action proposed; APK has not been executed.",
            "timestamp": time.time(),
        }],
    }


def pending_action(workflow: dict, action_id: str) -> dict:
    if not isinstance(workflow, dict) or workflow.get("policy_version") != WORKFLOW_POLICY_VERSION:
        raise ValueError("unsupported or missing workflow")
    matches = [p for p in workflow.get("proposals", []) if p.get("id") == action_id]
    if len(matches) != 1 or matches[0].get("status") != "pending":
        raise ValueError("action is not pending approval")
    if matches[0].get("kind") not in ACTION_CONFIGS:
        raise ValueError("action is not allowlisted")
    action = deepcopy(matches[0])
    policy = ACTION_CONFIGS[action["kind"]]
    # Execution always uses the server policy, never mutable/persisted client data.
    action["config"] = {
        "duration": policy["duration"],
        "use_frida": policy["use_frida"],
        "use_ui_agent": policy["use_ui_agent"],
        "ui_agent_mode": policy["ui_agent_mode"],
    }
    return action


def _observation(result: dict, action: dict) -> dict:
    network = result.get("network") or {}
    frida = result.get("frida") or {}
    ui = result.get("ui_agent") or {}
    return {
        "id": "runtime-" + uuid.uuid4().hex[:10],
        "action_id": action["id"],
        "action_kind": action["kind"],
        "ran": bool(result.get("ran")),
        "duration": result.get("duration"),
        "dynamic_score": result.get("dynamic_score", 0),
        "final_score": result.get("final_score"),
        "final_severity": result.get("final_severity"),
        "runtime_signals": list(result.get("runtime_signals") or [])[:30],
        "network": {
            "urls": list(network.get("urls") or [])[:30],
            "domains": list(network.get("domains") or [])[:30],
            "ips": list(network.get("ips") or [])[:30],
        },
        "frida": {
            "ran": bool(frida.get("ran")),
            "event_count": frida.get("event_count", 0),
            "findings": list(frida.get("findings") or [])[:30],
            "reason": str(frida.get("reason") or "")[:500],
        },
        "ui_agent": {
            "status": ui.get("status"),
            "mode": ui.get("mode"),
            "steps_used": ui.get("steps_used", 0),
            "vision_actions": ui.get("vision_actions", 0),
            "reason": str(ui.get("reason") or "")[:500],
        },
        "crash_count": len(result.get("crashes") or []),
        "reason": str(result.get("reason") or "")[:500],
        "timestamp": time.time(),
    }


def record_result(workflow: dict, action_id: str, result: dict) -> tuple[dict, dict]:
    updated = deepcopy(workflow)
    action = pending_action(updated, action_id)
    for proposal in updated["proposals"]:
        if proposal.get("id") == action_id:
            proposal["status"] = "completed"
            proposal["approved_at"] = time.time()
            proposal["completed_at"] = time.time()
    observation = _observation(result, action)
    updated.setdefault("observations", []).append(observation)
    updated.setdefault("audit", []).append({
        "step": len(updated.get("audit", [])) + 1,
        "event": "approved_action_completed",
        "status": "completed" if observation["ran"] else "warning",
        "action_id": action_id,
        "action_kind": action["kind"],
        "detail": "User-approved sandbox action completed and produced a bounded observation.",
        "timestamp": time.time(),
    })
    updated["status"] = "reviewing"
    return updated, observation


def advance(workflow: dict, analysis: dict, observation: dict, investigation: dict,
            *, ui_enabled: bool, vision_enabled: bool) -> dict:
    """Choose at most one next action after the agent reviews runtime evidence."""
    updated = deepcopy(workflow)
    updated.setdefault("agent_reviews", []).append(deepcopy(investigation))
    capabilities = _static_capabilities(analysis)
    completed = {p.get("kind") for p in updated.get("proposals", []) if p.get("status") == "completed"}
    next_kind = None
    reason = ""

    if "dynamic_frida" not in completed and capabilities["packed_or_dynamic"]:
        next_kind = "dynamic_frida"
        reason = "Static packing or runtime-loading evidence warrants instrumented observation."
    elif "dynamic_frida" not in completed and (
            observation.get("runtime_signals") or observation.get("network", {}).get("urls")):
        next_kind = "dynamic_frida"
        reason = "Baseline runtime signals warrant targeted Frida hooks for attribution."
    elif ui_enabled and "dynamic_ui_tree" not in completed and capabilities["ui_relevant"]:
        next_kind = "dynamic_ui_tree"
        reason = "UI-relevant fraud capabilities warrant bounded synthetic interaction."
    elif (ui_enabled and vision_enabled and updated.get("allow_vision", False)
          and "dynamic_ui_vision" not in completed
          and observation.get("ui_agent", {}).get("status") in {"blocked", "no_actions"}):
        next_kind = "dynamic_ui_vision"
        reason = "UI-tree exploration could not progress; vision assistance is available."

    if next_kind:
        proposal = _proposal(next_kind, reason, investigation)
        updated.setdefault("proposals", []).append(proposal)
        updated["status"] = "approval_required"
        detail = f"Agent review completed; proposed {proposal['title']}."
    else:
        updated["status"] = "completed"
        detail = "Agent review completed; no additional allowlisted action is justified."
    updated.setdefault("audit", []).append({
        "step": len(updated.get("audit", [])) + 1,
        "event": "runtime_review_completed",
        "status": updated["status"],
        "action_id": updated.get("proposals", [])[-1].get("id") if next_kind else None,
        "detail": detail,
        "timestamp": time.time(),
    })
    return updated
