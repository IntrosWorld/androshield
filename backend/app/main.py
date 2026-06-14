"""FastAPI app: APK intake, static analysis, Gemini report, PDF export + dashboard.

Serves both the JSON API and the static single-page dashboard so the whole demo
runs from one `uvicorn app.main:app` process.
"""
import logging
import os
import tempfile

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles

# Load backend/.env regardless of where uvicorn is launched from.
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("main")

from .analyzer import static_analyzer, risk_scoring
from .genai import gemini_client
from .intel import virustotal, apkid_scan
from .ml import classifier as ml_classifier
from .dynamic import sandbox as dyn_sandbox, frida_runner
from . import db, report as report_pdf

MAX_UPLOAD_MB = 200
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))

app = FastAPI(title="APK Fraud Analyzer", version="1.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


@app.on_event("startup")
def _startup():
    db.init_db()
    ready = static_analyzer.engine_available()
    log.info("DB initialised. Gemini key present: %s | analyzer engine ready: %s",
             bool(os.getenv("GEMINI_API_KEY")), ready)
    if not ready:
        log.error("androguard is NOT importable in this interpreter — analysis will fail. "
                  "Start the server from backend/.venv (run: .\\.venv\\Scripts\\Activate.ps1).")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "gemini_configured": bool(os.getenv("GEMINI_API_KEY", "").strip()),
        "virustotal_configured": virustotal.is_configured(),
        "apkid_available": apkid_scan.available(),
        "ml_model_loaded": ml_classifier.available(),
        "analyzer_ready": static_analyzer.engine_available(),
        "dynamic": dyn_sandbox.status(),
        "frida_available": frida_runner.available(),
    }


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if not static_analyzer.engine_available():
        raise HTTPException(
            503,
            "Static-analysis engine (androguard) is not available in the server's Python "
            "environment. Start the server from backend/.venv so dependencies are loaded.",
        )
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Please upload a .apk file")

    data = await file.read()
    size_mb = len(data) / (1024 * 1024)
    if size_mb > MAX_UPLOAD_MB:
        raise HTTPException(413, f"File too large ({size_mb:.1f} MB > {MAX_UPLOAD_MB} MB)")

    # Write to a temp file for androguard; never executed.
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        # Preserve the original filename in the result.
        analysis = static_analyzer.analyze(tmp_path)
        analysis["file"]["filename"] = file.filename

        # VirusTotal corroboration (no-op if VT_API_KEY unset). Done before the LLM
        # so the report can cite real engine detections; folded into the risk score.
        if analysis.get("valid_apk"):
            vt = virustotal.lookup(
                analysis["file"].get("sha256"),
                domains=analysis.get("iocs", {}).get("domains", []),
                ips=analysis.get("iocs", {}).get("ips", []),
            )
            risk_scoring.apply_virustotal(analysis, vt)

        report = gemini_client.generate_report(analysis)
        sample_id = db.save_sample(analysis, report)

        return JSONResponse({
            "id": sample_id,
            "analysis": analysis,
            "report": report,
        })
    except Exception as e:
        log.exception("Analysis failed")
        raise HTTPException(500, f"Analysis failed: {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


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
    serial: str = Form(None),
):
    """Run the uploaded APK in the attached emulator and observe its behaviour.

    SAFETY: this is the controlled, opt-in exception to "never execute an uploaded APK".
    It runs ONLY inside the emulator the user has attached, never on the host. Use an
    isolated AVD for real malware.
    """
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Please upload a .apk file")
    st = dyn_sandbox.status()
    if not st.get("available"):
        raise HTTPException(503, st.get("reason", "No emulator/device available."))

    data = await file.read()
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        package, main_activity = _apk_identity(tmp_path)
        if not package:
            raise HTTPException(400, "Could not read package name — not a valid APK?")
        result = dyn_sandbox.run_dynamic(tmp_path, package, main_activity,
                                         duration=duration, use_frida=use_frida,
                                         serial=serial or None)
        result["filename"] = file.filename
        result["main_activity"] = main_activity
        return JSONResponse(result)
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Dynamic analysis failed")
        raise HTTPException(500, f"Dynamic analysis failed: {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


@app.get("/api/samples")
def samples():
    return {"samples": db.list_samples()}


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
