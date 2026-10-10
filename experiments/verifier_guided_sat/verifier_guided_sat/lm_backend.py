# Acronyms: JavaScript Object Notation (JSON).
"""Generic real-LM boundary for a local OpenAI-compatible chat endpoint."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from time import perf_counter_ns
from typing import Any, Mapping


class LmConfigurationError(RuntimeError):
    """A live backend is not configured without disclosing private values."""


class LmResponseError(RuntimeError):
    """A real backend response was unavailable or malformed."""

    def __init__(self, message: str, *, elapsed_ns: int) -> None:
        super().__init__(message)
        self.elapsed_ns = elapsed_ns


@dataclass(frozen=True)
class LmObservation:
    structured_output: dict[str, Any]
    elapsed_ns: int
    input_tokens: int | None
    output_tokens: int | None
    backend_class: str = "local OpenAI-compatible chat-completion endpoint"
    model_identity_disclosure: str = "withheld"

    def to_dict(self) -> dict[str, Any]:
        return {
            "structured_output": self.structured_output,
            "elapsed_ns": self.elapsed_ns,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "backend_class": self.backend_class,
            "model_identity_disclosure": self.model_identity_disclosure,
        }


class OpenAICompatibleBackend:
    """Small standard-library client; configuration is environment-only."""

    def __init__(self, base_url: str, api_key: str, model: str, timeout_seconds: int = 180) -> None:
        if not base_url or not model:
            raise LmConfigurationError("live LM endpoint and model must be configured")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_environment(cls) -> "OpenAICompatibleBackend":
        base_url = os.environ.get("VGSAT_LM_BASE_URL", "")
        model = os.environ.get("VGSAT_LM_MODEL", "")
        api_key = os.environ.get("VGSAT_LM_API_KEY", "")
        try:
            timeout = int(os.environ.get("VGSAT_LM_TIMEOUT_SECONDS", "180"))
        except ValueError as exc:
            raise LmConfigurationError("LM timeout must be an integer") from exc
        return cls(base_url, api_key, model, timeout)

    def public_configuration(self) -> dict[str, Any]:
        return {
            "backend_class": "local OpenAI-compatible chat-completion endpoint",
            "endpoint_disclosure": "withheld",
            "model_identity_disclosure": "withheld",
            "credential_source": "environment",
            "timeout_seconds": self.timeout_seconds,
            "sampling": {"temperature": 0, "top_p": 1},
        }

    def complete_json(self, system_prompt: str, user_prompt: str) -> LmObservation:
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "top_p": 1,
            "response_format": {"type": "json_object"},
        }
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = "Bearer " + self._api_key
        request = urllib.request.Request(
            self._base_url + "/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        started = perf_counter_ns()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                envelope = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            elapsed = perf_counter_ns() - started
            raise LmResponseError(
                f"real LM request failed: {type(exc).__name__}", elapsed_ns=elapsed
            ) from exc
        elapsed = perf_counter_ns() - started
        try:
            content = envelope["choices"][0]["message"]["content"]
            structured = _parse_json_object(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError, ValueError) as exc:
            raise LmResponseError(
                "real LM response did not contain one JSON object", elapsed_ns=elapsed
            ) from exc
        usage = envelope.get("usage") if isinstance(envelope, Mapping) else None
        return LmObservation(
            structured_output=structured,
            elapsed_ns=elapsed,
            input_tokens=_usage_int(usage, "prompt_tokens"),
            output_tokens=_usage_int(usage, "completion_tokens"),
        )


def _parse_json_object(content: Any) -> dict[str, Any]:
    if not isinstance(content, str):
        raise ValueError("content is not text")
    text = content.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1)
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("structured output is not an object")
    return parsed


def _usage_int(usage: Any, key: str) -> int | None:
    if not isinstance(usage, Mapping):
        return None
    value = usage.get(key)
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else None
