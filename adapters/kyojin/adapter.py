"""Kyojin OpenAI-compatible provider adapter for the AIOS runtime.

AIOS remains responsible for contract/permit authorization, effect lifecycle,
durable state, retries, and semantic verification. This adapter executes one
request only and returns a ProviderReceipt only for a valid HTTP response with
a valid chat-completions shape. Any ambiguity raises; core.runtime converts it
to UNKNOWN through the authoritative effect state machine.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from core.runtime import ProviderReceipt

Transport = Callable[[str, bytes, dict[str, str], float, int], tuple[int, bytes]]


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("base_url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain credentials, query, or fragment")
    return value.rstrip("/")


def _http_transport(
    url: str, body: bytes, headers: dict[str, str], timeout: float, max_response_bytes: int
) -> tuple[int, bytes]:
    request = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(max_response_bytes + 1)
            if len(raw) > max_response_bytes:
                raise ValueError("provider response exceeds configured size limit")
            return response.status, raw
    except HTTPError as exc:
        raw = exc.read(max_response_bytes + 1)
        if len(raw) > max_response_bytes:
            raise ValueError("provider error response exceeds configured size limit") from exc
        return exc.code, raw
    except (URLError, TimeoutError, OSError) as exc:
        # The remote side may have completed the generation before transport failed.
        raise TimeoutError(f"provider transport is ambiguous: {type(exc).__name__}") from exc


class KyojinAdapter:
    """Execute one inference call through a Kyojin-compatible chat endpoint.

    The authorized contract's scope is the prompt text. The model and endpoint
    are deployment configuration, not agent-controlled request overrides.
    """

    name = "kyojin.inference"

    def __init__(
        self,
        *,
        model: str | None = None,
        base_url: str | None = None,
        api_key_env: str = "KYOJIN_API_KEY",
        timeout_seconds: float = 60.0,
        max_tokens: int = 256,
        temperature: float = 0.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        transport: Transport = _http_transport,
    ) -> None:
        self.model = _text(model or os.environ.get("KYOJIN_MODEL"), "model")
        self.base_url = _validate_base_url(
            base_url or os.environ.get("KYOJIN_BASE_URL", "http://127.0.0.1:8000/v1")
        )
        self.api_key_env = _text(api_key_env, "api_key_env")
        if not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a finite positive number")
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens < 1:
            raise ValueError("max_tokens must be a positive integer")
        if not isinstance(temperature, (int, float)) or not math.isfinite(temperature) or not 0 <= temperature <= 2:
            raise ValueError("temperature must be finite and between 0 and 2")
        if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or max_response_bytes < 1:
            raise ValueError("max_response_bytes must be a positive integer")
        if not callable(transport):
            raise ValueError("transport must be callable")
        self.timeout_seconds = float(timeout_seconds)
        self.max_tokens = max_tokens
        self.temperature = float(temperature)
        self.max_response_bytes = max_response_bytes
        self._transport = transport

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        if not isinstance(contract, dict) or not contract:
            raise ValueError("contract must be a non-empty dict")
        if not isinstance(effect, dict) or not effect:
            raise ValueError("effect must be a non-empty dict")
        _text(attempt_id, "attempt_id")
        if not any(
            isinstance(item, str) and item.split("@", 1)[0] == self.name
            for item in contract.get("capabilities", [])
        ):
            raise PermissionError("Kyojin inference capability is not granted by contract")
        prompt = _text(contract.get("scope"), "contract.scope")
        effect_id = _text(effect.get("effect_id"), "effect.effect_id")
        if effect.get("attempt_id") != attempt_id:
            raise ValueError("effect attempt binding mismatch")

        payload = json.dumps(
            {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        api_key = os.environ.get(self.api_key_env)
        if api_key:
            headers["Authorization"] = "Bearer " + api_key

        status, raw = self._transport(
            self.base_url + "/chat/completions",
            payload,
            headers,
            self.timeout_seconds,
            self.max_response_bytes,
        )
        if not isinstance(status, int) or isinstance(status, bool):
            raise ValueError("provider transport returned an invalid HTTP status")
        if not isinstance(raw, bytes):
            raise ValueError("provider transport must return response bytes")
        if len(raw) > self.max_response_bytes:
            raise ValueError("provider response exceeds configured size limit")
        if not 200 <= status < 300:
            # Preserve uncertainty: the runtime's exception path records UNKNOWN.
            raise RuntimeError(f"Kyojin returned HTTP {status}; outcome not promoted")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Kyojin returned malformed JSON") from exc
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ValueError("Kyojin response missing choices[0]")
        message = choices[0].get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise ValueError("Kyojin response missing string message.content")
        output = message["content"]
        usage = {}
        usage_raw = data.get("usage")
        if isinstance(usage_raw, dict):
            for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
                value = usage_raw.get(field)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    usage[field] = value

        receipt = {
            "schema_version": "1.0",
            "state": "OBSERVED",
            "http_status": status,
            "model": self.model,
            "output": output,
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
            "usage": usage,
        }
        return ProviderReceipt(
            provider=self.name,
            effect_id=effect_id,
            attempt_id=attempt_id,
            provider_operation_id=f"{self.name}:{effect_id}:{attempt_id}",
            outcome="OBSERVED_SUCCESS",
            observation={"kyojin_receipt": receipt},
        )


__all__ = ["KyojinAdapter"]
