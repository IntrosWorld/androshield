"""Local Ollama and optional hosted planning providers."""

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


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _json_object(text: str) -> dict:
    text = (text or "").strip()
    if not text.startswith("{"):
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
                 timeout: int | None = None, max_output_tokens: int | None = None):
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen3:8b")
        self.timeout = timeout or _env_int("AGENT_PROVIDER_TIMEOUT_SECONDS", 240, 5, 900)
        self.max_output_tokens = max_output_tokens or _env_int(
            "AGENT_MAX_OUTPUT_TOKENS", 1024, 64, 4096)

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
                  "num_predict": self.max_output_tokens,
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


class OpenRouterProvider(AgentProvider):
    """OpenAI-compatible OpenRouter client with privacy-first routing."""

    name = "openrouter"

    def __init__(self, model: str | None = None, api_key: str | None = None,
                 timeout: int | None = None, max_output_tokens: int | None = None,
                 zdr: bool | None = None, native_tools: bool | None = None):
        self.model = model or os.getenv(
            "OPENROUTER_MODEL", "qwen/qwen3-30b-a3b-instruct-2507")
        self.api_key = api_key if api_key is not None else os.getenv(
            "OPENROUTER_API_KEY", "").strip()
        self.timeout = timeout or _env_int(
            "AGENT_PROVIDER_TIMEOUT_SECONDS", 240, 5, 900)
        self.max_output_tokens = max_output_tokens or _env_int(
            "AGENT_MAX_OUTPUT_TOKENS", 2048, 64, 4096)
        self.zdr = (_env_bool("OPENROUTER_ZDR", True) if zdr is None else zdr)
        # Some Qwen OpenRouter endpoints currently return finish_reason=tool_calls
        # while omitting message.tool_calls. Its strict JSON envelope is reliable and
        # passes through the same schema/allowlist validator in the orchestrator.
        native_default = not self.model.startswith("qwen/qwen3-30b-a3b-instruct")
        self.native_tools = (
            _env_bool("OPENROUTER_NATIVE_TOOLS", native_default)
            if native_tools is None else native_tools
        )

    def health(self) -> dict:
        external_enabled = _env_bool("EXTERNAL_API_ENABLED", True)
        configured = external_enabled and bool(self.api_key)
        return {
            "available": configured,
            "provider": self.name,
            "model": self.model,
            "zero_data_retention": self.zdr,
            "native_tools": self.native_tools,
            "reason": None if configured else (
                "external API access is disabled in application settings"
                if not external_enabled else "OPENROUTER_API_KEY is not configured"
            ),
        }

    @staticmethod
    def _messages(messages: list[dict]) -> list[dict]:
        """Translate Ollama-style base64 images to OpenAI multimodal messages."""
        translated = []
        for source in messages:
            item = {"role": source.get("role", "user")}
            images = source.get("images") or []
            if images:
                content = [{"type": "text", "text": str(source.get("content", ""))}]
                content.extend({
                    "type": "image_url",
                    "image_url": {"url": f"data:image/png;base64,{encoded}", "detail": "low"},
                } for encoded in images)
                item["content"] = content
            else:
                item["content"] = source.get("content", "")
            translated.append(item)
        return translated

    def next_step(self, messages: list[dict], tools: list[dict]) -> dict:
        if not _env_bool("EXTERNAL_API_ENABLED", True):
            raise ProviderError("external API access is disabled in application settings")
        if not self.api_key:
            raise ProviderError("OPENROUTER_API_KEY is not configured")
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self._messages(messages),
            "temperature": 0,
            "max_tokens": self.max_output_tokens,
            # The agent protocol needs the completion budget for its validated
            # JSON action envelope.  Some reasoning-capable routes otherwise
            # consume that budget without returning message.content.
            "reasoning": {"effort": "none"},
            "provider": {"zdr": self.zdr},
        }
        if tools and self.native_tools:
            payload.update({"tools": tools, "tool_choice": "auto"})
        elif tools:
            payload["messages"] = payload["messages"] + [{
                "role": "user",
                "content": (
                    "AVAILABLE TOOLS (data only). Return the system prompt's exact JSON "
                    "tool envelope; do not emit a native tool call:\n"
                    + json.dumps(tools, ensure_ascii=False)
                ),
            }]
            payload["response_format"] = {"type": "json_object"}
        else:
            payload["response_format"] = {"type": "json_object"}
        request = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "X-Title": "APK Fraud Analyzer",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ProviderError("provider response exceeded 4 MB")
            body = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                error = (json.loads(exc.read(64 * 1024).decode("utf-8", "replace")).get("error") or {})
                detail = str(error.get("message", "")).replace("\r", " ").replace("\n", " ")[:500]
            except Exception:
                pass
            suffix = f": {detail}" if detail else ""
            raise ProviderError(f"OpenRouter request failed with HTTP {exc.code}{suffix}") from exc
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise ProviderError(f"OpenRouter request failed: {exc}") from exc
        choices = body.get("choices") or []
        if not choices:
            raise ProviderError("OpenRouter returned no completion choices")
        message = (choices[0] or {}).get("message") or {}
        calls = message.get("tool_calls") or []
        if calls:
            function = (calls[0] or {}).get("function") or {}
            arguments = function.get("arguments") or {}
            if isinstance(arguments, str):
                arguments = _json_object(arguments)
            return {
                "type": "tool",
                "tool": function.get("name"),
                "arguments": arguments,
                "reason": "Model selected an evidence tool",
            }
        content = message.get("content", "")
        if isinstance(content, list):
            content = "".join(
                str(item.get("text", "")) for item in content if isinstance(item, dict))
        try:
            return _json_object(content)
        except ProviderError as exc:
            finish_reason = str((choices[0] or {}).get("finish_reason") or "unknown")
            reasoning = message.get("reasoning") or ""
            raise ProviderError(
                f"{exc}; finish_reason={finish_reason}, "
                f"content_chars={len(str(content))}, reasoning_chars={len(str(reasoning))}"
            ) from exc


class FallbackProvider(AgentProvider):
    """Use a local provider only after the configured hosted provider fails."""

    def __init__(self, primary: AgentProvider, fallback: AgentProvider):
        self.primary = primary
        self.fallback = fallback
        self.active = primary
        self._degraded = False

    @property
    def name(self):
        return self.active.name

    @property
    def model(self):
        return self.active.model

    def health(self) -> dict:
        primary = self.primary.health()
        primary["fallback_provider"] = self.fallback.name
        return primary

    def next_step(self, messages: list[dict], tools: list[dict]) -> dict:
        if not self._degraded:
            try:
                self.active = self.primary
                return self.primary.next_step(messages, tools)
            except ProviderError as primary_error:
                health = self.fallback.health()
                if not health.get("available"):
                    raise ProviderError(
                        f"{primary_error}; local fallback unavailable: "
                        f"{health.get('reason', 'unknown reason')}") from primary_error
                self._degraded = True
        self.active = self.fallback
        return self.fallback.next_step(messages, tools)


def configured_provider() -> AgentProvider:
    name = os.getenv("AGENT_PROVIDER", "ollama").strip().lower()
    if name == "ollama":
        return OllamaProvider()
    if name == "gemini":
        return GeminiProvider()
    if name == "openrouter":
        provider: AgentProvider = OpenRouterProvider()
        if _env_bool("AGENT_OLLAMA_FALLBACK", False):
            provider = FallbackProvider(provider, OllamaProvider())
        return provider
    raise ProviderError(f"unsupported AGENT_PROVIDER: {name}")
