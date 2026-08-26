"""FastAPI app: APK intake, static analysis, Gemini report, PDF export + dashboard.

Serves both the JSON API and the static single-page dashboard so the whole demo
runs from one `uvicorn app.main:app` process.
"""
import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import hashlib
import json
import logging
import os
import tempfile
import time
from ipaddress import ip_address

from dotenv import load_dotenv
from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

# Load backend/.env regardless of where uvicorn is launched from.
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("main")

from .analyzer import static_analyzer
from .genai import gemini_client
from .intel import virustotal, apkid_scan
from .ml import classifier as ml_classifier
from .dynamic import sandbox as dyn_sandbox, frida_runner, ui_agent
from .agent import orchestrator as agent_orchestrator
from .agent import workflow as agent_workflow
from . import analysis_service, db, optional_components, report as report_pdf, runtime_settings

MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "200"))
UPLOAD_CHUNK_BYTES = 1024 * 1024
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
_dynamic_analysis_lock = asyncio.Lock()
TEMP_UPLOAD_PREFIX = "apk-fraud-"
TEMP_UPLOAD_MAX_AGE_SECONDS = 24 * 60 * 60


def _remove_temporary_file(path: str | None) -> None:
    """Best-effort cleanup for an upload owned by this process."""
    if not path:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        log.warning("Could not remove temporary upload %s", path, exc_info=True)


def _remove_stale_temporary_uploads() -> None:
    """Remove only this application's abandoned uploads after an unclean stop."""
    directory = tempfile.gettempdir()
    cutoff = time.time() - TEMP_UPLOAD_MAX_AGE_SECONDS
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        if not (name.startswith(TEMP_UPLOAD_PREFIX) and name.endswith(".apk")):
            continue
        path = os.path.join(directory, name)
        try:
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                _remove_temporary_file(path)
        except OSError:
            continue


def _require_loopback(request: Request) -> None:
    """Keep machine-level settings inaccessible to LAN clients."""
    host = request.client.host if request.client else ""
    try:
        local = ip_address(host).is_loopback
    except ValueError:
        local = host in {"localhost", "testclient"}
    if not local:
        raise HTTPException(403, "Application settings are available only on this computer")


async def _spool_upload(file: UploadFile) -> tuple[str, int]:
    """Stream an upload to a temporary file with a hard byte limit.

    Reading the whole request before checking its length allowed a single large upload
    to exhaust server memory. This helper is shared by static and dynamic analysis and
    removes a partial temporary file on every failure path.
    """
    limit = MAX_UPLOAD_MB * 1024 * 1024
    path = None
    total = 0
    try:
        with tempfile.NamedTemporaryFile(
            delete=False, prefix=TEMP_UPLOAD_PREFIX, suffix=".apk",
        ) as tmp:
            path = tmp.name
            while True:
                chunk = await file.read(UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise HTTPException(
                        413, f"File too large (> {MAX_UPLOAD_MB} MB)"
                    )
                tmp.write(chunk)
        return path, total
    except BaseException:
        # asyncio.CancelledError derives from BaseException, not Exception. A client
        # disconnect must not leave a partially uploaded APK behind.
        _remove_temporary_file(path)
        raise


def _initialize_application() -> None:
    """Initialize persisted state and report optional capability health."""
    db.init_db()
    _remove_stale_temporary_uploads()
    runtime_settings.load_persisted()
    ready = static_analyzer.engine_available()
    log.info(
        "DB initialised. Gemini configured: %s | OpenRouter configured: %s | analyzer ready: %s",
        runtime_settings.external_services_enabled() and bool(os.getenv("GEMINI_API_KEY")),
        runtime_settings.external_services_enabled() and bool(os.getenv("OPENROUTER_API_KEY")),
        ready,
    )
    if not ready:
        log.error("androguard is NOT importable in this interpreter — analysis will fail. "
                  "Start the server from backend/.venv (run: .\\.venv\\Scripts\\Activate.ps1).")


@asynccontextmanager
async def _lifespan(_application: FastAPI) -> AsyncIterator[None]:
    _initialize_application()
    try:
        yield
    finally:
        # A worker thread cannot be cancelled safely while it is reading an APK. Drain
        # accepted jobs so each worker can persist its result and remove its temp file.
        # A forced process stop is recovered as an interrupted job on the next startup.
        tasks = list(_analysis_job_tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(title="APK Fraud Analyzer", version="1.0.0", lifespan=_lifespan)
cors_origins = [o.strip() for o in os.getenv(
    "CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000"
).split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware, allow_origins=cors_origins,
    allow_methods=["GET", "POST", "PUT"], allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "external_api_enabled": runtime_settings.external_services_enabled(),
        "gemini_configured": runtime_settings.external_services_enabled() and bool(os.getenv("GEMINI_API_KEY", "").strip()),
        "openrouter_configured": runtime_settings.external_services_enabled() and bool(os.getenv("OPENROUTER_API_KEY", "").strip()),
        "virustotal_configured": virustotal.is_configured(),
        "apkid_available": apkid_scan.available(),
        "ml_model_loaded": ml_classifier.available(),
        "ml_model": ml_classifier.model_info(),
        "analyzer_ready": static_analyzer.engine_available(),
        "dynamic": dyn_sandbox.status(),
        "frida_available": frida_runner.available(),
        "ui_agent": ui_agent.health(),
        "agentic": agent_orchestrator.agent_health(check_provider=False),
        "agentic_workflow": agent_workflow.health(),
        "analysis_capacity": analysis_service.capacity_status(),
        "analysis_queue": {
            "limit": analysis_service.queue_limit,
            "active_jobs": db.count_active_analysis_jobs(),
        },
        "database": db.database_health(),
        "dynamic_capacity": {
            "limit": 1,
            "active": int(_dynamic_analysis_lock.locked()),
        },
    }


@app.get("/api/settings")
def get_settings(request: Request):
    _require_loopback(request)
    return runtime_settings.public_settings()


@app.put("/api/settings")
def put_settings(request: Request, payload: dict = Body(...)):
    _require_loopback(request)
    try:
        return runtime_settings.update_settings(payload)
    except runtime_settings.SettingsError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/settings/test-provider")
def test_settings_provider(request: Request):
    _require_loopback(request)
    return agent_orchestrator.agent_health(check_provider=True)


@app.post("/api/settings/import-model")
def import_settings_model(request: Request, payload: dict = Body(...)):
    _require_loopback(request)
    try:
        return runtime_settings.import_gguf(
            payload.get("model_path", ""), payload.get("model_name", ""),
        )
    except runtime_settings.SettingsError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/components")
def get_components(request: Request):
    _require_loopback(request)
    return optional_components.component_catalog()


@app.post("/api/components/{component_id}/install")
def install_component(component_id: str, request: Request):
    _require_loopback(request)
    try:
        return optional_components.start_install(component_id)
    except optional_components.ComponentError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/components/jobs/{job_id}")
def component_job(job_id: str, request: Request):
    _require_loopback(request)
    try:
        return optional_components.get_job(job_id)
    except optional_components.ComponentError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/agent/health")
def agent_health():
    return agent_orchestrator.agent_health(check_provider=True)


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    """Compatibility endpoint that waits for the shared worker pipeline to finish."""
    if not static_analyzer.engine_available():
        raise HTTPException(
            503,
            "Static-analysis engine (androguard) is not available in the server's Python "
            "environment. Start the server from backend/.venv so dependencies are loaded.",
        )
    if not (file.filename or "").lower().endswith(".apk"):
        raise HTTPException(400, "Please upload a .apk file")

    # Write to a temp file for androguard; never executed.
    tmp_path = None
    try:
        tmp_path, _size = await _spool_upload(file)
        result = await run_in_threadpool(
            analysis_service.analyze_path, tmp_path, file.filename,
        )
        return JSONResponse(result)
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Analysis failed")
        raise HTTPException(500, "Analysis failed; see server logs for details") from e
    finally:
        _remove_temporary_file(tmp_path)


_analysis_job_tasks: set[asyncio.Task] = set()


def _analysis_job_progress(job_id: str):
    def update(phase: str, message: str) -> None:
        db.update_analysis_job(
            job_id, status="running", phase=phase, message=message,
        )
    return update


async def _run_analysis_job(
    job_id: str, apk_path: str, filename: str,
) -> None:
    try:
        db.update_analysis_job(
            job_id, status="running", phase="starting",
            message="Static-analysis worker started.",
        )
        result = await run_in_threadpool(
            analysis_service.analyze_path,
            apk_path,
            filename,
            progress=_analysis_job_progress(job_id),
        )
        db.update_analysis_job(
            job_id, status="completed", phase="completed",
            message="Analysis completed.", sample_id=result["id"], error=None,
        )
    except asyncio.CancelledError:
        db.update_analysis_job(
            job_id, status="failed", phase="interrupted",
            message="Analysis was interrupted before completion.",
            error="Analysis interrupted",
        )
        raise
    except Exception:
        log.exception("Background analysis job %s failed", job_id)
        db.update_analysis_job(
            job_id, status="failed", phase="failed",
            message="Analysis failed; see server logs for details.",
            error="Analysis failed",
        )
    finally:
        _remove_temporary_file(apk_path)


@app.post("/api/analysis-jobs", status_code=202)
async def create_analysis_job(file: UploadFile = File(...)):
    """Queue an APK analysis and return immediately with a persistent job ID."""
    if not static_analyzer.engine_available():
        raise HTTPException(503, "Static-analysis engine is not available")
    filename = file.filename or ""
    if not filename.lower().endswith(".apk"):
        raise HTTPException(400, "Please upload a .apk file")
    active_jobs = await run_in_threadpool(db.count_active_analysis_jobs)
    if active_jobs >= analysis_service.queue_limit:
        raise HTTPException(429, "Analysis queue is full; try again after a job completes")

    apk_path = None
    handed_to_worker = False
    try:
        apk_path, _size = await _spool_upload(file)
        job = await run_in_threadpool(
            db.create_analysis_job,
            filename, active_limit=analysis_service.queue_limit,
        )
        if not job:
            raise HTTPException(429, "Analysis queue is full; try again after a job completes")
        task = asyncio.create_task(_run_analysis_job(job["id"], apk_path, filename))
        _analysis_job_tasks.add(task)
        task.add_done_callback(_analysis_job_tasks.discard)
        handed_to_worker = True
        return {
            **job,
            "status_url": f"/api/analysis-jobs/{job['id']}",
        }
    except BaseException:
        if not handed_to_worker:
            _remove_temporary_file(apk_path)
        raise


@app.get("/api/analysis-jobs/{job_id}")
def analysis_job(job_id: str):
    job = db.get_analysis_job(job_id)
    if not job:
        raise HTTPException(404, "Analysis job not found")
    if job.get("sample_id"):
        job["result_url"] = f"/api/samples/{job['sample_id']}"
    return job


@app.post("/api/agent/investigate/{sample_id}")
async def investigate_sample(sample_id: str):
    """Run the bounded agent over saved extracted evidence; never reopens the APK."""
    config = agent_orchestrator.agent_health(check_provider=False)
    if not config["enabled"]:
        raise HTTPException(409, "Agentic investigation is disabled; set AGENT_ENABLED=true")
    saved = db.get_sample(sample_id)
    if not saved:
        raise HTTPException(404, "Sample not found")
    analysis = saved["analysis"]
    if not analysis.get("valid_apk") or analysis.get("risk_score") is None:
        raise HTTPException(409, "Agentic investigation requires completed static findings")
    score_before = (
        analysis.get("risk_score"), analysis.get("severity"),
        list(analysis.get("score_breakdown", [])),
    )
    investigation = await run_in_threadpool(agent_orchestrator.run_investigation, analysis)
    score_after = (
        analysis.get("risk_score"), analysis.get("severity"),
        list(analysis.get("score_breakdown", [])),
    )
    if score_after != score_before:
        log.critical("Agent attempted to alter deterministic scoring state")
        raise HTTPException(500, "Agent scoring invariant failed")
    investigation = gemini_client.review_investigation(analysis, investigation)
    analysis["agentic"] = investigation
    refreshed_report = gemini_client.generate_report(analysis)
    if not db.update_sample_artifacts(sample_id, analysis, refreshed_report):
        raise HTTPException(404, "Sample disappeared during investigation")
    return {"id": sample_id, "agentic": investigation, "report": refreshed_report}


def _set_workflow_progress(sample_id: str, phase: str, message: str, *, reset: bool = False, **details):
    state = (
        {"active": True, "phase": phase, "events": []}
        if reset
        else db.get_workflow_progress(sample_id)
        or {"active": True, "phase": phase, "events": []}
    )
    event = {
        "phase": str(phase)[:50], "message": str(message)[:300],
        "timestamp": time.time(),
        **{key: value for key, value in details.items()
           if key in {"step", "action", "reason", "status", "evidence_count",
                      "hypothesis_count", "gap_count", "error", "force_final"}},
    }
    state["phase"] = event["phase"]
    state["active"] = phase not in {"completed", "failed"}
    state.setdefault("events", []).append(event)
    state["events"] = state["events"][-40:]
    db.save_workflow_progress(sample_id, state)


def _agent_progress_callback(sample_id: str):
    def update(event: dict):
        _set_workflow_progress(
            sample_id, event.get("phase", "reviewing"),
            event.get("message", "Review activity updated."),
            **{key: value for key, value in event.items() if key not in {"phase", "message"}},
        )
    return update


@app.get("/api/agent/workflow/{sample_id}/status")
async def agent_workflow_status(sample_id: str):
    saved = await run_in_threadpool(db.get_sample, sample_id)
    if not saved:
        raise HTTPException(404, "Sample not found")
    workflow = (saved.get("analysis") or {}).get("agentic_workflow") or {}
    workflow_summary = None if not workflow else {
        "status": workflow.get("status"),
        "allow_vision": bool(workflow.get("allow_vision")),
        "proposals": [
            {"id": item.get("id"), "kind": item.get("kind"), "status": item.get("status")}
            for item in (workflow.get("proposals") or [])[:10]
        ],
    }
    return {
        "id": sample_id,
        "workflow": workflow_summary,
        "progress": db.get_workflow_progress(sample_id) or {
            "active": False, "phase": "idle", "events": [],
        },
    }


@app.post("/api/agent/workflow/{sample_id}")
async def start_agent_workflow(sample_id: str, allow_vision: bool = False):
    """Start the separate approval-controlled investigation workflow.

    This does not execute the APK. It runs/reuses the existing read-only evidence
    investigation and creates one pending sandbox proposal.
    """
    if not agent_workflow.health()["enabled"]:
        raise HTTPException(409, "Agentic workflow is disabled; enable it in Settings")
    if not agent_orchestrator.agent_health(check_provider=False)["enabled"]:
        raise HTTPException(409, "AI Review must also be enabled")
    saved = db.get_sample(sample_id)
    if not saved:
        raise HTTPException(404, "Sample not found")
    analysis = saved["analysis"]
    if not analysis.get("valid_apk") or analysis.get("risk_score") is None:
        raise HTTPException(409, "Agentic workflow requires completed static findings")

    existing = analysis.get("agentic") or {}
    existing_workflow = analysis.get("agentic_workflow") or {}
    if existing_workflow.get("policy_version") == agent_workflow.WORKFLOW_POLICY_VERSION:
        return {
            "id": sample_id,
            "workflow": existing_workflow,
            "agentic": existing,
            "report": saved.get("report") or {},
        }
    _set_workflow_progress(
        sample_id, "planning", "Starting Agentic Investigation planning.", reset=True,
    )
    if existing.get("status") == "completed":
        investigation = existing
    else:
        score_before = (
            analysis.get("risk_score"), analysis.get("severity"),
            list(analysis.get("score_breakdown", [])),
        )
        investigation = await run_in_threadpool(
            agent_orchestrator.run_investigation, analysis,
            progress_callback=_agent_progress_callback(sample_id),
        )
        score_after = (
            analysis.get("risk_score"), analysis.get("severity"),
            list(analysis.get("score_breakdown", [])),
        )
        if score_after != score_before:
            raise HTTPException(500, "Agent scoring invariant failed")
        investigation = gemini_client.review_investigation(analysis, investigation)
        analysis["agentic"] = investigation

    workflow = agent_workflow.start(analysis, investigation, allow_vision=allow_vision)
    analysis["agentic_workflow"] = workflow
    refreshed_report = gemini_client.generate_report(analysis)
    if not db.update_sample_artifacts(sample_id, analysis, refreshed_report):
        raise HTTPException(404, "Sample disappeared during workflow creation")
    _set_workflow_progress(
        sample_id, "completed", "Planning completed; baseline approval is ready.",
    )
    return {
        "id": sample_id,
        "workflow": workflow,
        "agentic": investigation,
        "report": refreshed_report,
    }


def _sha256_path(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_dedicated_sandbox(status: dict, requested_serial: str | None) -> str:
    """Resolve an Agentic Investigation target to the dedicated analysis AVD.

    Manual analysis may deliberately target another connected emulator. The guided
    workflow makes a stronger isolation promise, so it never accepts that override.
    """
    target_serial = requested_serial or status.get("serial")
    target = next(
        (device for device in status.get("devices", [])
         if device.get("serial") == target_serial),
        None,
    )
    if not target or target.get("avd_name") != dyn_sandbox.DEFAULT_SANDBOX_AVD:
        raise HTTPException(
            400,
            f"Agentic Investigation requires the dedicated AVD "
            f"'{dyn_sandbox.DEFAULT_SANDBOX_AVD}'",
        )
    return str(target_serial)


_workflow_approval_lock = asyncio.Lock()


@app.post("/api/agent/workflow/{sample_id}/approve")
async def approve_agent_workflow_action(
    sample_id: str,
    file: UploadFile = File(...),
    action_id: str = Form(...),
    serial: str = Form(None),
):
    # Serialize approval claims within this process so a double-click cannot replay the
    # same pending action before its completed state is persisted.
    _set_workflow_progress(
        sample_id, "approval_validating", "Validating the approved action and APK identity.",
        reset=True, action=action_id,
    )
    try:
        async with _workflow_approval_lock:
            return await _approve_agent_workflow_action(sample_id, file, action_id, serial)
    except Exception as exc:
        _set_workflow_progress(
            sample_id, "failed", "The approved action stopped before completion.",
            error=str(exc)[:300],
        )
        raise


async def _approve_agent_workflow_action(
    sample_id: str,
    file: UploadFile,
    action_id: str,
    serial: str | None,
):
    """Approve and execute exactly one server-proposed sandbox configuration."""
    if not agent_workflow.health()["enabled"]:
        raise HTTPException(409, "Agentic workflow is disabled; enable it in Settings")
    if not agent_orchestrator.agent_health(check_provider=False)["enabled"]:
        raise HTTPException(409, "AI Review must also be enabled")
    saved = db.get_sample(sample_id)
    if not saved:
        raise HTTPException(404, "Sample not found")
    analysis = saved["analysis"]
    workflow = analysis.get("agentic_workflow") or {}
    if (analysis.get("risk_score") != workflow.get("static_score_snapshot")
            or analysis.get("severity") != workflow.get("static_severity_snapshot")):
        raise HTTPException(409, "Static verdict changed after this workflow was created; start a new case")
    try:
        action = agent_workflow.pending_action(workflow, action_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc

    sandbox_status = dyn_sandbox.status()
    if not sandbox_status.get("available"):
        raise HTTPException(503, sandbox_status.get("reason", "No emulator/device available."))
    sandbox_serial = _require_dedicated_sandbox(sandbox_status, serial)

    # Verify the re-uploaded bytes against the saved case before invoking the existing
    # dynamic endpoint. The raw APK is never persisted in the workflow or database.
    verify_path = None
    try:
        verify_path, _size = await _spool_upload(file)
        expected_hash = str((analysis.get("file") or {}).get("sha256") or "").lower()
        if not expected_hash or _sha256_path(verify_path).lower() != expected_hash:
            raise HTTPException(400, "Re-uploaded APK does not match this investigation")
    finally:
        _remove_temporary_file(verify_path)
    await file.seek(0)

    config = action["config"]
    _set_workflow_progress(
        sample_id, "sandbox_running",
        f"Running approved {action['title']} in the isolated emulator.",
        action=action["kind"],
    )
    dynamic_response = await dynamic_analyze(
        file=file,
        duration=int(config["duration"]),
        use_frida=bool(config["use_frida"]),
        use_ui_agent=bool(config["use_ui_agent"]),
        serial=sandbox_serial,
        ui_agent_mode=str(config["ui_agent_mode"]),
    )
    dynamic_result = json.loads(dynamic_response.body.decode("utf-8"))
    _set_workflow_progress(
        sample_id, "sandbox_completed",
        "Sandbox pass completed; converting output into bounded evidence.",
        action=action["kind"],
    )
    workflow, observation = agent_workflow.record_result(workflow, action_id, dynamic_result)
    analysis["agentic_workflow"] = workflow

    score_before = (
        analysis.get("risk_score"), analysis.get("severity"),
        list(analysis.get("score_breakdown", [])),
    )
    _set_workflow_progress(
        sample_id, "evidence_review", "Reviewing the new runtime evidence with the selected model.",
    )
    investigation = await run_in_threadpool(
        agent_orchestrator.run_investigation, analysis,
        progress_callback=_agent_progress_callback(sample_id),
    )
    score_after = (
        analysis.get("risk_score"), analysis.get("severity"),
        list(analysis.get("score_breakdown", [])),
    )
    if score_after != score_before:
        raise HTTPException(500, "Agent scoring invariant failed")
    investigation = gemini_client.review_investigation(analysis, investigation)
    workflow = agent_workflow.advance(
        workflow, analysis, observation, investigation,
        ui_enabled=ui_agent.health()["enabled"],
        vision_enabled=ui_agent.health()["vision_enabled"],
    )
    analysis["agentic_workflow"] = workflow
    refreshed_report = gemini_client.generate_report(analysis)
    if not db.update_sample_artifacts(sample_id, analysis, refreshed_report):
        raise HTTPException(404, "Sample disappeared while saving workflow result")
    _set_workflow_progress(
        sample_id, "completed",
        "Review completed; the next approved action or final stop decision is ready.",
        status=workflow.get("status"),
    )
    return {
        "id": sample_id,
        "workflow": workflow,
        "dynamic": dynamic_result,
        "agentic_review": investigation,
        "report": refreshed_report,
    }


def _apk_identity(apk_path):
    """Fast package + main-activity extraction (no full static analysis)."""
    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
        return a.get_package(), a.get_main_activity()
    except Exception:
        return None, None


@app.post("/api/dynamic")
async def dynamic_analyze(
    file: UploadFile = File(...),
    duration: int = Form(15),
    use_frida: bool = Form(False),
    use_ui_agent: bool = Form(False),
    serial: str = Form(None),
    ui_agent_mode: str = Form("tree"),
):
    """Run the uploaded APK in the attached emulator and observe its behaviour.

    SAFETY: this is the controlled, opt-in exception to "never execute an uploaded APK".
    It runs ONLY inside the emulator the user has attached, never on the host. Use an
    isolated AVD for real malware.
    """
    if not (file.filename or "").lower().endswith(".apk"):
        raise HTTPException(400, "Please upload a .apk file")
    st = dyn_sandbox.status()
    if not st.get("available"):
        raise HTTPException(503, st.get("reason", "No emulator/device available."))
    if use_ui_agent and not ui_agent.health()["enabled"]:
        raise HTTPException(409, "AI UI Explorer is disabled; set UI_AGENT_ENABLED=true")
    ui_agent_mode = (ui_agent_mode if isinstance(ui_agent_mode, str) else "tree")
    ui_agent_mode = (ui_agent_mode or "tree").strip().lower()
    if use_ui_agent and ui_agent_mode not in {"tree", "vision"}:
        raise HTTPException(400, "UI-agent mode must be 'tree' or 'vision'")
    if use_ui_agent and ui_agent_mode == "vision" and not ui_agent.health()["vision_enabled"]:
        raise HTTPException(409, "Vision-assisted UI exploration is disabled on this server")
    if use_ui_agent and use_frida:
        raise HTTPException(400, "Run Frida and AI UI Explorer as separate passes")

    tmp_path = None
    try:
        if serial:
            connected = {d.get("serial") for d in st.get("devices", [])}
            if serial not in connected:
                raise HTTPException(400, "Selected emulator/device is not connected")
        target_serial = serial or st.get("serial")
        if use_ui_agent:
            target = next((d for d in st.get("devices", [])
                           if d.get("serial") == target_serial), None)
            if not target or target.get("avd_name") != dyn_sandbox.DEFAULT_SANDBOX_AVD:
                raise HTTPException(
                    400,
                    f"AI UI Explorer may run only on dedicated AVD "
                    f"'{dyn_sandbox.DEFAULT_SANDBOX_AVD}'",
                )
        tmp_path, _size = await _spool_upload(file)
        package, main_activity = _apk_identity(tmp_path)
        if not package:
            raise HTTPException(400, "Could not read package name — not a valid APK?")
        async with _dynamic_analysis_lock:
            result = await run_in_threadpool(
                dyn_sandbox.run_dynamic,
                tmp_path,
                package,
                main_activity,
                duration=duration,
                use_frida=use_frida,
                serial=target_serial,
                use_ui_agent=use_ui_agent,
                ui_agent_mode=ui_agent_mode,
            )
        result["filename"] = file.filename
        result["main_activity"] = main_activity
        return JSONResponse(result)
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Dynamic analysis failed")
        raise HTTPException(
            500, "Dynamic analysis failed; see server logs for details",
        ) from e
    finally:
        _remove_temporary_file(tmp_path)


@app.get("/api/samples")
def samples(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return {"samples": db.list_samples(limit=limit, offset=offset)}


@app.get("/api/samples/{sample_id}")
def sample(sample_id: str):
    s = db.get_sample(sample_id)
    if not s:
        raise HTTPException(404, "Sample not found")
    return s


def _flatten_iocs(sample):
    a = sample["analysis"]
    i = a.get("iocs", {}) or {}
    rows = []
    for typ, key in [("url", "urls"), ("domain", "domains"), ("ip", "ips"),
                     ("telegram_token", "telegram_tokens"), ("secret", "hardcoded_secrets"),
                     ("firebase", "firebase_endpoints")]:
        for v in i.get(key, []) or []:
            rows.append({"type": typ, "value": v})
    rows.append({"type": "sha256", "value": a.get("file", {}).get("sha256", "")})
    rows.append({"type": "md5", "value": a.get("file", {}).get("md5", "")})
    if a.get("manifest", {}).get("package_name"):
        rows.append({"type": "package", "value": a["manifest"]["package_name"]})
    for d in (a.get("virustotal", {}) or {}).get("flagged_domains", []) or []:
        rows.append({"type": "vt_flagged_domain", "value": d["domain"]})
    return [r for r in rows if r["value"]]


@app.get("/api/samples/{sample_id}/iocs.json")
def sample_iocs_json(sample_id: str):
    s = db.get_sample(sample_id)
    if not s:
        raise HTTPException(404, "Sample not found")
    return {"sample_id": sample_id, "package": s.get("package_name"),
            "sha256": s.get("sha256"), "iocs": _flatten_iocs(s)}


@app.get("/api/samples/{sample_id}/iocs.csv")
def sample_iocs_csv(sample_id: str):
    s = db.get_sample(sample_id)
    if not s:
        raise HTTPException(404, "Sample not found")
    lines = ["type,value"]
    for r in _flatten_iocs(s):
        val = r["value"].replace('"', '""')
        lines.append(f'{r["type"]},"{val}"')
    csv_data = "\n".join(lines)
    fname = (s.get("package_name") or "iocs").replace(".", "_") + "_iocs.csv"
    return Response(content=csv_data, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.get("/api/samples/{sample_id}/report.pdf")
def sample_pdf(sample_id: str):
    s = db.get_sample(sample_id)
    if not s:
        raise HTTPException(404, "Sample not found")
    pdf = report_pdf.build_pdf(s["analysis"], s["report"])
    fname = (s.get("package_name") or "apk_report").replace(".", "_") + "_report.pdf"
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# --- Static dashboard (mounted last so /api/* takes priority) ---
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
