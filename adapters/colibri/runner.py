"""Governed adapter for a separately installed Colibri OpenAI-compatible server.

Colibri supplies inference only. AIOS remains responsible for permit/authority,
effect lifecycle, receipt validation, durable state, verification and promotion.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from core.runtime import ProviderReceipt

COLIBRI_CAPABILITY = "colibri.inference@1"
_DEFAULT_MAX_REQUEST_BYTES = 128 * 1024
_DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024


def _nonempty(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _loopback_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("base_url must be an absolute HTTP(S) URL")
    host = parsed.hostname.lower()
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        raise PermissionError("Colibri endpoint must be loopback unless remote access is explicitly designed")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain credentials, query, or fragment")
    return value.rstrip("/")


@dataclass(frozen=True)
class ColibriAdapter:
    """Perform one bounded chat-completion request against local Colibri."""

    model: str
    base_url: str = "http://127.0.0.1:8000/v1"
    name: str = "colibri.inference"
    timeout_seconds: float = 60.0
    max_request_bytes: int = _DEFAULT_MAX_REQUEST_BYTES
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES
    opener: Callable | None = None

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        _nonempty(self.name, "provider name")
        _nonempty(self.model, "model")
        _nonempty(attempt_id, "attempt_id")
        if not isinstance(contract, dict) or not contract:
            raise ValueError("contract must be a non-empty object")
        if COLIBRI_CAPABILITY not in contract.get("capabilities", []):
            raise PermissionError("Colibri inference capability is not granted by contract")
        if "external_effect" not in contract.get("allowed_effects", []):
            raise PermissionError("external effect is not authorized by contract")
        if not isinstance(effect, dict) or not effect:
            raise ValueError("effect must be a non-empty object")
        effect_id = _nonempty(effect.get("effect_id"), "effect.effect_id")
        if effect.get("attempt_id") != attempt_id:
            raise ValueError("effect attempt binding mismatch")
        if effect.get("state") not in ("DISPATCHED", "EXECUTING"):
            raise RuntimeError("effect must be dispatched before Colibri execution")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) or not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if (not isinstance(self.max_request_bytes, int) or isinstance(self.max_request_bytes, bool) or self.max_request_bytes < 1\n                or not isinstance(self.max_response_bytes, int) or isinstance(self.max_response_bytes, bool) or self.max_response_bytes < 1):
            raise ValueError("request and response limits must be positive")

        payload = effect.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("effect.payload must be an object")
        messages = payload.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("effect.payload.messages must be a non-empty list")
        for message in messages:
            if not isinstance(message, dict) or message.get("role") not in ("system", "user", "assistant"):
                raise ValueError("each message must have a supported role")
            _nonempty(message.get("content"), "message.content")
        max_tokens = payload.get("max_tokens", 512)
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or not 1 <= max_tokens <= 8192:
            raise ValueError("max_tokens must be an integer between 1 and 8192")
        request_obj = {"model": self.model, "messages": messages, "max_tokens": max_tokens}
        if "temperature" in payload:
            temperature = payload["temperature"]
            if not isinstance(temperature, (int, float)) or isinstance(temperature, bool) or not 0 <= temperature <= 2:
                raise ValueError("temperature must be between 0 and 2")
            request_obj["temperature"] = temperature
        request_bytes = json.dumps(request_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(request_bytes) > self.max_request_bytes:
            raise ValueError("Colibri request exceeds input limit")

        base_url = _loopback_url(self.base_url)
        endpoint = base_url + "/chat/completions"
        request_digest = hashlib.sha256(request_bytes).hexdigest()
        request = urllib.request.Request(
            endpoint, data=request_bytes,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        opener = self.opener or urllib.request.urlopen
        try:
            with opener(request, timeout=self.timeout_seconds) as response:
                status = getattr(response, "status", 200)
                if status < 200 or status >= 300:
                    raise RuntimeError(f"Colibri returned HTTP {status}")
                raw = response.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Colibri returned HTTP {exc.code}") from exc
        if len(raw) > self.max_response_bytes:
            raise ValueError("Colibri response exceeds output limit")
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Colibri response is not valid JSON") from exc
        if not isinstance(result, dict):
            raise ValueError("Colibri response must be an object")
        choices = result.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ValueError("Colibri response has no choices")
        message = choices[0].get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise ValueError("Colibri response has no textual message")
        response_id = result.get("id")
        _nonempty(response_id, "response.id")
        usage = result.get("usage")
        if usage is not None and not isinstance(usage, dict):
            raise ValueError("response.usage must be an object when present")
        observation = {
            "response_id": response_id,
            "request_sha256": request_digest,
            "endpoint": endpoint,
            "model": result.get("model", self.model),
            "message": message,
            "finish_reason": choices[0].get("finish_reason"),
        }
        if usage is not None:
            observation["usage"] = usage
        return ProviderReceipt(
            provider=self.name,
            effect_id=effect_id,
            attempt_id=attempt_id,
            provider_operation_id=f"colibri:{response_id}",
            outcome="OBSERVED_SUCCESS",
            observation={"colibri_response": observation},
        )


__all__ = ["COLIBRI_CAPABILITY", "ColibriAdapter"]
