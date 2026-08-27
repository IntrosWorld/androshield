"""Deterministic composition of static and runtime risk scores.

The component scores remain untouched. Runtime evidence may only raise the final
score, and only until the shared 100-point ceiling is reached.
"""
from __future__ import annotations

from ..analyzer.risk_scoring import severity_for


def combine(static_score: int, dynamic_score: int) -> dict:
    """Return an explainable final score without mutating either input score."""
    static = max(0, min(int(static_score), 100))
    dynamic = max(0, min(int(dynamic_score), 100))
    runtime_contribution = min(dynamic, 100 - static)
    final = static + runtime_contribution
    capped_points = dynamic - runtime_contribution
    breakdown = [{
        "category": "Static analysis baseline",
        "points": static,
        "detail": "Existing explainable static risk score; unchanged by the sandbox run.",
    }]
    if runtime_contribution:
        breakdown.append({
            "category": "Observed runtime behaviour",
            "points": runtime_contribution,
            "detail": (
                f"Dynamic rule engine produced {dynamic} point(s); "
                f"{runtime_contribution} fit below the 100-point final-score cap."
            ),
        })
    return {
        "static_score": static,
        "dynamic_score": dynamic,
        "final_score": final,
        "final_severity": severity_for(final),
        "final_score_breakdown": breakdown,
        "final_score_method": "static_plus_dynamic_capped_v1",
        "dynamic_points_capped": capped_points,
    }


def bounded_summary(result: dict) -> dict:
    """Keep only reportable runtime evidence in persisted sample history."""
    network = result.get("network") or {}
    return {
        "available": bool(result.get("available", True)),
        "ran": bool(result.get("ran")),
        "duration": result.get("duration"),
        "use_frida": bool(result.get("use_frida")),
        "use_ui_agent": bool(result.get("use_ui_agent")),
        "dynamic_score": result.get("dynamic_score", 0),
        "static_score": result.get("static_score"),
        "final_score": result.get("final_score"),
        "final_severity": result.get("final_severity"),
        "final_score_breakdown": list(result.get("final_score_breakdown") or [])[:5],
        "final_score_method": result.get("final_score_method"),
        "dynamic_points_capped": result.get("dynamic_points_capped", 0),
        "score_breakdown": list(result.get("score_breakdown") or [])[:30],
        "runtime_signals": list(result.get("runtime_signals") or [])[:30],
        "network": {
            "urls": list(network.get("urls") or [])[:30],
            "domains": list(network.get("domains") or [])[:30],
            "ips": list(network.get("ips") or [])[:30],
        },
        "granted_permissions": list(result.get("granted_permissions") or [])[:30],
        "services": list(result.get("services") or [])[:30],
        "crashes": list(result.get("crashes") or [])[:10],
        "timestamp": result.get("timestamp"),
    }
