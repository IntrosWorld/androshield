"""Optional runtime feature packs downloaded from trusted upstream sources."""

from __future__ import annotations

import json
import lzma
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from . import external_tools


REPO_ROOT = Path(__file__).resolve().parents[2]
JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()
MODEL_PACKS = {
    "agent-model-fast": {
        "model": "qwen3:1.7b", "name": "Local AI, fast", "size": "about 1.4 GB",
        "description": "Recommended CPU-friendly model for bounded evidence investigation.",
    },
    "agent-model-quality": {
        "model": "qwen3:4b", "name": "Local AI, balanced", "size": "about 2.5 GB",
        "description": "Slower local model with stronger report and action consistency.",
    },
}


class ComponentError(RuntimeError):
    pass


def _sdk_root() -> Path | None:
    return external_tools.sdk_root()


def _sdk_tool(root: Path | None, name: str) -> Path | None:
    if not root:
        return None
    suffix = ".bat" if os.name == "nt" else ""
    candidates = [
        root / "cmdline-tools" / "latest" / "bin" / f"{name}{suffix}",
        root / "tools" / "bin" / f"{name}{suffix}",
    ]
    return next((path for path in candidates if path.is_file()), None)


def _ollama_models() -> set[str]:
    base = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
    try:
        with urllib.request.urlopen(base + "/api/tags", timeout=3) as response:
            body = json.loads(response.read(4 * 1024 * 1024).decode("utf-8"))
        return {item.get("name") for item in body.get("models", []) if item.get("name")}
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return set()


def _frida_version() -> str:
    try:
        import frida
        return str(frida.__version__)
    except Exception:
        return ""


def _frida_cache_path(version: str) -> Path:
    selected = os.getenv("APK_FRIDA_SERVER_PATH", "").strip()
    if selected:
        return external_tools.resolve_path(selected)
    storage = Path(os.getenv("APK_DESKTOP_DATA_DIR") or REPO_ROOT)
    return storage / "tools" / "frida" / f"frida-server-{version}-x86_64"


def _sandbox_avd_exists(root: Path | None) -> bool:
    emulator = external_tools.emulator_path(root)
    if not emulator:
        return False
    try:
        completed = subprocess.run(
            [str(emulator), "-list-avds"], capture_output=True, text=True,
            timeout=8, check=False, env=external_tools.subprocess_environment(),
        )
        return "FraudSandbox" in {line.strip() for line in completed.stdout.splitlines()}
    except (OSError, subprocess.TimeoutExpired):
        return False


def component_catalog() -> dict:
    installed_models = _ollama_models()
    ollama_available = bool(external_tools.executable("APK_OLLAMA_PATH", "ollama"))
    components = []
    for component_id, spec in MODEL_PACKS.items():
        components.append({
            "id": component_id, "name": spec["name"], "kind": "model",
            "description": spec["description"], "download_size": spec["size"],
            "source_name": "Ollama model registry", "source_url": "https://ollama.com/library/qwen3",
            "installed": spec["model"] in installed_models,
            "install_available": ollama_available,
            "unavailable_reason": "Ollama is not installed" if not ollama_available else "",
            "action_label": "Download and use",
        })

    root = _sdk_root()
    sdkmanager = _sdk_tool(root, "sdkmanager")
    avdmanager = _sdk_tool(root, "avdmanager")
    system_image = bool(root and (root / "system-images" / "android-35" / "google_apis" / "x86_64").is_dir())
    emulator = bool(external_tools.emulator_path(root))
    avd_exists = _sandbox_avd_exists(root)
    components.append({
        "id": "android-sandbox", "name": "Android analysis sandbox", "kind": "sandbox",
        "description": "Google Android emulator, API 35 image, platform tools, and isolated FraudSandbox AVD.",
        "download_size": "typically 8 to 12 GB", "source_name": "Google Android SDK",
        "source_url": "https://developer.android.com/tools/sdkmanager",
        "installed": system_image and emulator and avd_exists,
        "install_available": bool(sdkmanager and avdmanager),
        "unavailable_reason": "Install Android SDK Command-line Tools first" if not (sdkmanager and avdmanager) else "",
        "action_label": "Install sandbox files",
    })

    frida_version = _frida_version()
    frida_path = _frida_cache_path(frida_version) if frida_version else None
    components.append({
        "id": "frida-server", "name": "Frida instrumentation", "kind": "instrumentation",
        "description": "Matching x86_64 frida-server for runtime hooks and unpacking in the emulator.",
        "download_size": "typically under 30 MB", "source_name": "Frida GitHub releases",
        "source_url": "https://github.com/frida/frida/releases",
        "installed": bool(frida_path and frida_path.is_file()),
        "install_available": bool(frida_version),
        "unavailable_reason": "The Python Frida package is not installed" if not frida_version else "",
        "action_label": "Download instrumentation",
    })
    return {"components": components, "research_datasets_included": False}


def _set_job(job_id: str, **values) -> None:
    with _LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(values)


def _run_model_install(job_id: str, component_id: str) -> None:
    spec = MODEL_PACKS[component_id]
    ollama = external_tools.executable("APK_OLLAMA_PATH", "ollama")
    if not ollama:
        raise ComponentError("Ollama is not installed")
    _set_job(job_id, message=f"Downloading {spec['model']} from Ollama...")
    completed = subprocess.run(
        [ollama, "pull", spec["model"]], capture_output=True, text=True,
        timeout=7200, check=False, env=external_tools.subprocess_environment(),
    )
    if completed.returncode != 0:
        raise ComponentError((completed.stderr or completed.stdout or "Ollama download failed")[-1500:])
    from . import runtime_settings
    runtime_settings.update_settings({"ollama_model": spec["model"]})


def _run_sandbox_install(job_id: str) -> None:
    root = _sdk_root()
    if not root or not _sdk_tool(root, "sdkmanager"):
        raise ComponentError("Android SDK Command-line Tools are required")
    _set_job(job_id, message="Downloading Android emulator and API 35 sandbox files from Google...")
    if os.name == "nt":
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
        resources = Path(os.getenv("APK_DESKTOP_RESOURCE_DIR") or REPO_ROOT)
        script = resources / "scripts" / "install_sandbox_components.ps1"
        if not powershell or not script.is_file():
            raise ComponentError("PowerShell sandbox installer is unavailable")
        command = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-SdkRoot", str(root)]
    else:
        sdkmanager = str(_sdk_tool(root, "sdkmanager"))
        command = [sdkmanager, f"--sdk_root={root}", "--install", "platform-tools", "emulator", "system-images;android-35;google_apis;x86_64"]
    completed = subprocess.run(
        command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=10800, check=False, env=external_tools.subprocess_environment(),
    )
    if completed.returncode != 0:
        detail = completed.stderr or completed.stdout or "Android SDK download failed"
        raise ComponentError(detail[-2000:])


def _run_frida_install(job_id: str) -> None:
    if os.getenv("APK_FRIDA_SERVER_PATH", "").strip():
        raise ComponentError("Clear the manually selected Frida server path before downloading a managed copy")
    version = _frida_version()
    if not version:
        raise ComponentError("The Python Frida package is not installed")
    destination = _frida_cache_path(version)
    destination.parent.mkdir(parents=True, exist_ok=True)
    asset = f"frida-server-{version}-android-x86_64.xz"
    url = f"https://github.com/frida/frida/releases/download/{version}/{asset}"
    _set_job(job_id, message=f"Downloading Frida {version} from GitHub...")
    request = urllib.request.Request(url, headers={"User-Agent": "AndroShield"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            compressed = response.read(128 * 1024 * 1024 + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise ComponentError(f"Frida download failed: {exc}") from exc
    if len(compressed) > 128 * 1024 * 1024:
        raise ComponentError("Frida download exceeded the 128 MB safety limit")
    try:
        data = lzma.decompress(compressed)
    except lzma.LZMAError as exc:
        raise ComponentError("Downloaded Frida archive was invalid") from exc
    temporary = destination.with_suffix(".partial")
    temporary.write_bytes(data)
    temporary.replace(destination)


def _worker(job_id: str, component_id: str) -> None:
    try:
        if component_id in MODEL_PACKS:
            _run_model_install(job_id, component_id)
        elif component_id == "android-sandbox":
            _run_sandbox_install(job_id)
        elif component_id == "frida-server":
            _run_frida_install(job_id)
        else:
            raise ComponentError("Unknown optional component")
        _set_job(job_id, status="completed", message="Download completed and the feature is ready.", finished_at=time.time())
    except Exception as exc:
        _set_job(job_id, status="failed", message=str(exc), finished_at=time.time())


def _start_worker(job_id: str, component_id: str) -> None:
    _set_job(job_id, status="running")
    _worker(job_id, component_id)


def start_install(component_id: str) -> dict:
    allowed = set(MODEL_PACKS) | {"android-sandbox", "frida-server"}
    if component_id not in allowed:
        raise ComponentError("Unknown optional component")
    catalog_item = next(item for item in component_catalog()["components"] if item["id"] == component_id)
    if catalog_item["installed"]:
        return {"already_installed": True, "component_id": component_id}
    if not catalog_item["install_available"]:
        raise ComponentError(catalog_item["unavailable_reason"])
    with _LOCK:
        existing = next((job for job in JOBS.values() if job["component_id"] == component_id and job["status"] in {"queued", "running"}), None)
        if existing:
            return dict(existing)
        job_id = uuid.uuid4().hex[:12]
        job = {"id": job_id, "component_id": component_id, "status": "queued", "message": "Preparing download...", "started_at": time.time()}
        JOBS[job_id] = job
    thread = threading.Thread(target=_start_worker, args=(job_id, component_id), daemon=True)
    thread.start()
    return dict(job)


def get_job(job_id: str) -> dict:
    with _LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise ComponentError("Download job not found")
        return dict(job)
