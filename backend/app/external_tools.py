"""Resolve user-selected tools without executing them or silently replacing a bad path."""
import os
import shutil
from pathlib import Path

PATH_FIELDS = {
    "android_sdk_dir": ("APK_ANDROID_SDK_ROOT", "directory"),
    "adb_executable": ("APK_ADB_PATH", "file"),
    "emulator_executable": ("APK_EMULATOR_PATH", "file"),
    "android_avd_dir": ("ANDROID_AVD_HOME", "directory"),
    "java_home": ("JAVA_HOME", "directory"),
    "ollama_executable": ("APK_OLLAMA_PATH", "file"),
    "frida_server_path": ("APK_FRIDA_SERVER_PATH", "file"),
    "static_model_path": ("APK_STATIC_MODEL_PATH", "file"),
}


def resolve_path(value: str) -> Path:
    path = Path(os.path.expandvars(value)).expanduser()
    if not path.is_absolute():
        path = Path(os.getenv("APK_DESKTOP_DATA_DIR") or os.getcwd()) / path
    return path.resolve()


def executable(env: str, name: str) -> str | None:
    selected = os.getenv(env, "").strip()
    if selected:
        path = resolve_path(selected)
        return str(path) if path.is_file() else None
    return shutil.which(name)


def sdk_root() -> Path | None:
    selected = os.getenv("APK_ANDROID_SDK_ROOT", "").strip()
    if selected:
        root = resolve_path(selected)
        return root if root.is_dir() else None
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.getenv(env, "").strip()
        if value and resolve_path(value).is_dir():
            return resolve_path(value)
    adb = executable("APK_ADB_PATH", "adb")
    if adb:
        return Path(adb).resolve().parent.parent
    return None


def adb_path() -> str | None:
    if os.getenv("APK_ADB_PATH", "").strip():
        return executable("APK_ADB_PATH", "adb")
    root = sdk_root()
    if root:
        candidate = root / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
        if candidate.is_file():
            return str(candidate)
    # An explicitly selected SDK must never quietly use a different SDK's adb.
    return None if os.getenv("APK_ANDROID_SDK_ROOT", "").strip() else shutil.which("adb")


def emulator_path(root=None) -> str | None:
    if os.getenv("APK_EMULATOR_PATH", "").strip():
        return executable("APK_EMULATOR_PATH", "emulator")
    root = root or sdk_root()
    if root:
        candidate = root / "emulator" / ("emulator.exe" if os.name == "nt" else "emulator")
        if candidate.is_file():
            return str(candidate)
    return None if os.getenv("APK_ANDROID_SDK_ROOT", "").strip() else shutil.which("emulator")


def status() -> dict:
    resolved = {
        "android_sdk_dir": sdk_root(), "adb_executable": adb_path(),
        "emulator_executable": emulator_path(),
        "ollama_executable": executable("APK_OLLAMA_PATH", "ollama"),
    }
    result = {}
    for field, (env, kind) in PATH_FIELDS.items():
        configured = os.getenv(env, "").strip()
        location = resolve_path(configured) if configured else resolved.get(field)
        found = bool(location and (Path(location).is_dir() if kind == "directory" else Path(location).is_file()))
        result[field] = {"path": str(location) if location else "", "available": found,
                         "source": "configured" if configured else "detected" if found else "not configured"}
    return result


def subprocess_environment() -> dict:
    env = os.environ.copy()
    for key in ("JAVA_HOME", "ANDROID_AVD_HOME", "OLLAMA_MODELS"):
        if env.get(key, "").strip():
            env[key] = str(resolve_path(env[key]))
    if env.get("APK_ANDROID_SDK_ROOT", "").strip():
        env["ANDROID_HOME"] = env["ANDROID_SDK_ROOT"] = str(resolve_path(env["APK_ANDROID_SDK_ROOT"]))
    if env.get("OLLAMA_BASE_URL"):
        env["OLLAMA_HOST"] = env["OLLAMA_BASE_URL"]
    return env
