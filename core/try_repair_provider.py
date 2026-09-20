"""Validation-only client helpers for the TRY-owned reasoning provider.

AIOS owns authority, mutation and verification. TRY owns the external model
credential. This module contains no Gemini endpoint or credential handling.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Mapping
from urllib.parse import urlparse


class TryRepairProviderError(RuntimeError):
    pass


_DENIED_PREFIXES = (".github/workflows/", ".aios/", "secrets/")
_DENIED_NAMES = {".env", ".env.local", ".env.production", "credentials.json"}


def _validate_patch_paths(payload: Mapping[str, Any]) -> None:
    for item in payload["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("content"), str):
            raise TryRepairProviderError("provider returned invalid patch file")
        path = item["path"].replace("\\", "/")
        parts = path.split("/")
        if (
            path.startswith("/")
            or ".." in parts
            or path in _DENIED_NAMES
            or path.startswith("tests/")
            or any(path == p.rstrip("/") or path.startswith(p) for p in _DENIED_PREFIXES)
        ):
            raise TryRepairProviderError("provider returned protected patch path")


def validate_proposal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise TryRepairProviderError("provider response is not an object")
    if payload.get("status") == "HOLD":
        return {"status": "HOLD", "reason": str(payload.get("reason") or "provider_hold")}
    if payload.get("schema") != 2 or not isinstance(payload.get("files"), list) or not payload["files"]:
        raise TryRepairProviderError("provider returned invalid proposal schema")
    _validate_patch_paths(payload)
    return dict(payload)


def _open(req: urllib.request.Request, timeout: int):
    host = (urlparse(req.full_url).hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout)
    return urllib.request.urlopen(req, timeout=timeout)


def health() -> dict[str, Any]:
    url = os.environ.get("TRY_REPAIR_PROVIDER_URL", "").strip()
    token = os.environ.get("TRY_REPAIR_PROVIDER_TOKEN", "")
    if not url or not token:
        raise TryRepairProviderError("TRY provider endpoint/token not configured")
    req = urllib.request.Request(
        url.rstrip("/") + "/healthz",
        headers={"Authorization": "Bearer " + token},
        method="GET",
    )
    try:
        with _open(req, int(os.environ.get("TRY_REPAIR_PROVIDER_TIMEOUT", "10"))) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise TryRepairProviderError(f"provider health failed: {type(exc).__name__}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("status") != "READY":
        raise TryRepairProviderError("provider health is not READY")
    return payload


def propose(*, request_id: str, repository: str, sha: str, attempt: int,
            failure: Mapping[str, Any], source: Mapping[str, str]) -> dict[str, Any]:
    url = os.environ.get("TRY_REPAIR_PROVIDER_URL", "").strip()
    token = os.environ.get("TRY_REPAIR_PROVIDER_TOKEN", "")
    if not url or not token:
        raise TryRepairProviderError("TRY provider endpoint/token not configured")
    if not request_id or len(sha) != 40:
        raise TryRepairProviderError("invalid provider request identity")
    body = {
        "request_id": request_id,
        "repository": repository,
        "sha": sha,
        "attempt": int(attempt),
        "failure": dict(failure),
        "source_snapshot": dict(source),
    }
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/repair/propose",
        data=json.dumps(body, sort_keys=True).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with _open(req, int(os.environ.get("TRY_REPAIR_PROVIDER_TIMEOUT", "120"))) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise TryRepairProviderError(f"provider request failed: {type(exc).__name__}: {exc}") from exc
    payload = validate_proposal(payload)
    if payload.get("status") == "HOLD":
        return payload
    payload["request_id"] = request_id
    payload["base_sha"] = sha
    payload["attempt"] = int(attempt)
    return payload


__all__ = ["TryRepairProviderError", "health", "propose", "validate_proposal"]
