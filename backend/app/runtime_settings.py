"""Validated, persisted settings for the local analyst application."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from . import db


BOOL_FIELDS = {
    "external_api_enabled": ("EXTERNAL_API_ENABLED", True),
    "agent_enabled": ("AGENT_ENABLED", False),
    "agent_auto_run": ("AGENT_AUTO_RUN", False),
    "agent_gemini_review": ("AGENT_GEMINI_REVIEW", False),
}
INT_FIELDS = {
    "agent_max_steps": ("AGENT_MAX_STEPS", 8, 1, 20),
    "agent_max_tool_calls": ("AGENT_MAX_TOOL_CALLS", 4, 1, 19),
    "agent_time_budget_seconds": ("AGENT_TIME_BUDGET_SECONDS", 420, 10, 3600),
    "agent_provider_timeout_seconds": ("AGENT_PROVIDER_TIMEOUT_SECONDS", 240, 5, 900),
    "agent_context_tokens": ("AGENT_CONTEXT_TOKENS", 4096, 2048, 32768),
}
TEXT_FIELDS = {
    "agent_provider": ("AGENT_PROVIDER", "ollama"),
    "ollama_base_url": ("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
    "ollama_model": ("OLLAMA_MODEL", "qwen3:8b"),
    "ollama_models_dir": ("OLLAMA_MODELS", ""),
    "gemini_model": ("GEMINI_MODEL", "gemini-2.0-flash"),
}
SECRET_FIELDS = {
    "gemini_api_key": "GEMINI_API_KEY",
    "virustotal_api_key": "VT_API_KEY",
}
MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class SettingsError(ValueError):
    pass


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def external_services_enabled() -> bool:
    return _bool_env("EXTERNAL_API_ENABLED", True)


def load_persisted() -> None:
    for key, value in db.get_runtime_settings(include_secrets=True).items():
        os.environ[key] = value


def public_settings() -> dict:
    result = {
        key: _bool_env(env, default) for key, (env, default) in BOOL_FIELDS.items()
    }
    result.update({
        key: _int_env(env, default, minimum, maximum)
        for key, (env, default, minimum, maximum) in INT_FIELDS.items()
    })
    result.update({key: os.getenv(env, default) for key, (env, default) in TEXT_FIELDS.items()})
    result["gemini_key_configured"] = bool(os.getenv("GEMINI_API_KEY", "").strip())
    result["virustotal_key_configured"] = bool(os.getenv("VT_API_KEY", "").strip())
    result["ollama_cli_available"] = bool(shutil.which("ollama"))
    return result


def _clean_text(value, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise SettingsError(f"{field} must be text")
    value = value.strip()
    if any(ch in value for ch in "\r\n\x00") or len(value) > maximum:
        raise SettingsError(f"{field} contains unsupported characters or is too long")
    return value


def update_settings(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise SettingsError("settings payload must be an object")
    allowed = set(BOOL_FIELDS) | set(INT_FIELDS) | set(TEXT_FIELDS) | set(SECRET_FIELDS) | {
        "clear_gemini_api_key", "clear_virustotal_api_key",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise SettingsError(f"unsupported setting: {unknown[0]}")

    persisted: dict[str, tuple[str, bool]] = {}
    deleted: list[str] = []
    for key, (env, _default) in BOOL_FIELDS.items():
        if key in payload:
            if not isinstance(payload[key], bool):
                raise SettingsError(f"{key} must be true or false")
            persisted[env] = ("true" if payload[key] else "false", False)
    for key, (env, _default, minimum, maximum) in INT_FIELDS.items():
        if key in payload:
            value = payload[key]
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise SettingsError(f"{key} must be between {minimum} and {maximum}")
            persisted[env] = (str(value), False)
    for key, (env, _default) in TEXT_FIELDS.items():
        if key not in payload:
            continue
        value = _clean_text(payload[key], key)
        if key == "agent_provider" and value not in {"ollama", "gemini"}:
            raise SettingsError("agent_provider must be ollama or gemini")
        if key == "ollama_base_url":
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise SettingsError("ollama_base_url must be an HTTP or HTTPS URL without credentials")
        if key in {"ollama_model", "gemini_model"} and not MODEL_NAME_RE.fullmatch(value):
            raise SettingsError(f"{key} is not a valid model name")
        persisted[env] = (value, False)
    for key, env in SECRET_FIELDS.items():
        if key in payload:
            value = _clean_text(payload[key], key, maximum=4096)
            if value:
                persisted[env] = (value, True)
        clear_key = f"clear_{key}"
        if payload.get(clear_key) is True:
            persisted.pop(env, None)
            deleted.append(env)

    db.save_runtime_settings(persisted)
    db.delete_runtime_settings(deleted)
    for env, (value, _secret) in persisted.items():
        os.environ[env] = value
    for env in deleted:
        os.environ.pop(env, None)
    return public_settings()


def import_gguf(path_value: str, model_name: str) -> dict:
    path_text = _clean_text(path_value, "model_path", maximum=2048)
    name = _clean_text(model_name, "model_name", maximum=128)
    if not MODEL_NAME_RE.fullmatch(name):
        raise SettingsError("model_name contains unsupported characters")
    source = Path(path_text).expanduser().resolve()
    if source.suffix.lower() != ".gguf" or not source.is_file():
        raise SettingsError("model_path must point to an existing .gguf file")
    ollama = shutil.which("ollama")
    if not ollama:
        raise SettingsError("Ollama CLI was not found. Install or start Ollama first")
    from_path = source.as_posix().replace('"', '\\"')
    with tempfile.TemporaryDirectory(prefix="apk-analyzer-model-") as temp_dir:
        modelfile = Path(temp_dir) / "Modelfile"
        modelfile.write_text(f'FROM "{from_path}"\n', encoding="utf-8")
        try:
            completed = subprocess.run(
                [ollama, "create", name, "--file", str(modelfile)],
                capture_output=True, text=True, timeout=1800, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SettingsError("Ollama model import timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Ollama import failed").strip()
        raise SettingsError(detail[-1000:])
    update_settings({"ollama_model": name})
    return {"imported": True, "model": name, "source": str(source)}
