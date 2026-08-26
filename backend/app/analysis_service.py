"""Synchronous static-analysis pipeline with explicit local capacity control.

FastAPI routes dispatch this service to a worker thread. Keeping the expensive,
blocking pipeline here makes both request/response analysis and persisted background
jobs share exactly the same behavior and score invariants.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from . import db
from .agent import orchestrator as agent_orchestrator
from .analyzer import risk_scoring, static_analyzer
from .genai import gemini_client
from .intel import virustotal


ProgressCallback = Callable[[str, str], None]


def _configured_concurrency() -> int:
    try:
        value = int(os.getenv("STATIC_ANALYSIS_CONCURRENCY", "2"))
    except (TypeError, ValueError):
        value = 2
    return max(1, min(value, 8))


def _configured_queue_limit() -> int:
    try:
        value = int(os.getenv("STATIC_ANALYSIS_QUEUE_LIMIT", "20"))
    except (TypeError, ValueError):
        value = 20
    return max(1, min(value, 200))


class AnalysisCapacity:
    """Bound CPU-heavy analyses while exposing queue depth for health reporting."""

    def __init__(self, limit: int):
        self.limit = limit
        self._semaphore = threading.BoundedSemaphore(limit)
        self._state_lock = threading.Lock()
        self._active = 0
        self._waiting = 0

    @contextmanager
    def slot(self, progress: ProgressCallback) -> Iterator[None]:
        with self._state_lock:
            self._waiting += 1
        progress("queued", "Waiting for static-analysis capacity.")
        self._semaphore.acquire()
        with self._state_lock:
            self._waiting -= 1
            self._active += 1
        try:
            yield
        finally:
            with self._state_lock:
                self._active -= 1
            self._semaphore.release()

    def snapshot(self) -> dict:
        with self._state_lock:
            return {
                "limit": self.limit,
                "active": self._active,
                "waiting": self._waiting,
            }


capacity = AnalysisCapacity(_configured_concurrency())
queue_limit = _configured_queue_limit()


def capacity_status() -> dict:
    return capacity.snapshot()


def _score_snapshot(analysis: dict) -> tuple:
    return (
        analysis.get("risk_score"),
        analysis.get("severity"),
        list(analysis.get("score_breakdown", [])),
    )


def analyze_path(
    apk_path: str,
    filename: str,
    *,
    progress: ProgressCallback | None = None,
) -> dict:
    """Analyze one spooled APK and persist its report.

    The raw APK remains local to ``apk_path`` and is removed by the caller. Only
    extracted findings may reach optional external intelligence or language models.
    """
    notify = progress or (lambda _phase, _message: None)
    with capacity.slot(notify):
        notify("static_analysis", "Extracting deterministic APK evidence.")
        analysis = static_analyzer.analyze(apk_path)
        analysis["file"]["filename"] = filename

        if analysis.get("valid_apk"):
            notify("intelligence", "Checking optional hash and IOC corroboration.")
            intelligence = virustotal.lookup(
                analysis["file"].get("sha256"),
                domains=analysis.get("iocs", {}).get("domains", []),
                ips=analysis.get("iocs", {}).get("ips", []),
            )
            risk_scoring.apply_virustotal(analysis, intelligence)

        agent_config = agent_orchestrator.agent_health(check_provider=False)
        if analysis.get("valid_apk") and agent_config["enabled"] and agent_config["auto_run"]:
            notify("ai_review", "Reviewing extracted evidence with the selected model.")
            score_before = _score_snapshot(analysis)
            investigation = agent_orchestrator.run_investigation(analysis)
            if _score_snapshot(analysis) != score_before:
                raise RuntimeError("agent invariant violated: deterministic score changed")
            analysis["agentic"] = gemini_client.review_investigation(
                analysis, investigation,
            )

        notify("reporting", "Generating and storing the analyst report.")
        report = gemini_client.generate_report(analysis)
        sample_id = db.save_sample(analysis, report)
        notify("completed", "Analysis completed.")
        return {"id": sample_id, "analysis": analysis, "report": report}
