"""Local Ollama and optional Gemini planning providers."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any


class ProviderError(RuntimeError):
    pass


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _json_object(text: str) -> dict:
    text = (text or "").strip()
    if text.startswith("```"):
        start, end = text.find("{"), text.rfind("}")
        text = text[start:end + 1] if start >= 0 and end > start else ""
    try:
        value = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ProviderError("model did not return a JSON action") from exc
    if not isinstance(value, dict):
        raise ProviderError("model action must be a JSON object")
    return value


class AgentProvider(ABC):
    name = "provider"
    model = "unknown"

    @abstractmethod
    def next_step(self, messages: list[dict], tools: list[dict]) -> dict:
        raise NotImplementedError

    def health(self) -> dict:
        return {"available": True, "provider": self.name, "model": self.model}


class OllamaProvider(AgentProvider):
    name = "ollama"

    def __init__(self, base_url: str | None = None, model: str | None = None,
                 timeout: int | None = None):
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen3:8b")
        self.timeout = timeout or _env_int("AGENT_PROVIDER_TIMEOUT_SECONDS", 240, 5, 900)

    def _request(self, path: str, payload: dict | None = None) -> dict:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path, data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise ProviderError("provider response exceeded 4 MB")
                return json.loads(raw.decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise ProviderError(f"Ollama request failed: {exc}") from exc

    def health(self) -> dict:
        try:
            tags = self._request("/api/tags")
            names = {item.get("name") for item in tags.get("models", [])}
            return {
                "available": self.model in names,
                "provider": self.name,
                "model": self.model,
                "installed_models": sorted(name for name in names if name),
                "reason": None if self.model in names else f"model {self.model} is not installed",
            }
        except ProviderError as exc:
            return {"available": False, "provider": self.name, "model": self.model, "reason": str(exc)}

    def next_step(self, messages: list[dict], tools: list[dict]) -> dict:
        response = self._request("/api/chat", {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "stream": False,
            "think": False,
            "options": {
                "temperature": 0,
                "num_ctx": _env_int("AGENT_CONTEXT_TOKENS", 4096, 2048, 32768),
            },
        })
        message = response.get("message") or {}
        calls = message.get("tool_calls") or []
        if calls:
            function = (calls[0] or {}).get("function") or {}
            return {
                "type": "tool",
                "tool": function.get("name"),
                "arguments": function.get("arguments") or {},
                "reason": "Model selected an evidence tool",
            }
        return _json_object(message.get("content", ""))


class GeminiProvider(AgentProvider):
    name = "gemini"

    def __init__(self, model: str | None = None):
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    def health(self) -> dict:
        external_enabled = os.getenv("EXTERNAL_API_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
        configured = external_enabled and bool(os.getenv("GEMINI_API_KEY", "").strip())
        return {
            "available": configured, "provider": self.name, "model": self.model,
            "reason": None if configured else (
                "external API access is disabled in application settings"
                if not external_enabled else "GEMINI_API_KEY is not configured"
            ),
        }

    def next_step(self, messages: list[dict], tools: list[dict]) -> dict:
        if os.getenv("EXTERNAL_API_ENABLED", "true").strip().lower() not in {"1", "true", "yes", "on"}:
            raise ProviderError("external API access is disabled in application settings")
        key = os.getenv("GEMINI_API_KEY", "").strip()
        if not key:
            raise ProviderError("GEMINI_API_KEY is not configured")
        try:
            import google.generativeai as genai
            genai.configure(api_key=key)
            model = genai.GenerativeModel(
                self.model,
                system_instruction=messages[0]["content"],
                generation_config={
                    "response_mime_type": "application/json", "temperature": 0,
                    "max_output_tokens": 2048,
                },
            )
            prompt = json.dumps({"conversation": messages[1:], "available_tools": tools}, ensure_ascii=False)
            response = model.generate_content(prompt)
            return _json_object(response.text)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(f"Gemini request failed: {exc}") from exc


def configured_provider() -> AgentProvider:
    name = os.getenv("AGENT_PROVIDER", "ollama").strip().lower()
    if name == "ollama":
        return OllamaProvider()
    if name == "gemini":
        return GeminiProvider()
    raise ProviderError(f"unsupported AGENT_PROVIDER: {name}")
