"""Validation-only client helpers for the TRY-owned reasoning provider.

AIOS owns authority, mutation and verification. TRY owns the external model
credential. This module contains no Gemini endpoint or credential handling.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import time
from typing import Any, Mapping
from urllib.parse import urlparse


class TryRepairProviderError(RuntimeError):
    pass


_RETRYABLE_HTTP = {500, 502, 503, 504}
_PROVIDER_RETRY_ATTEMPTS = 3
_PROVIDER_RETRY_BACKOFF = (1, 2)


_DENIED_PREFIXES = (".github/", ".aios/", "secrets/", ".git/")
_DENIED_NAMES = {".env", ".env.local", ".env.production", "credentials.json"}
_DENIED_COMPONENTS = {".git", ".github", ".aios", "secrets", "tests"}


def _validate_patch_paths(payload: Mapping[str, Any]) -> None:
    seen: set[str] = set()
    for item in payload["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("content"), str):
            raise TryRepairProviderError("provider returned invalid patch file")
        path = item["path"].replace("\\", "/")
        parts = path.split("/")
        if not path or any(part in {"", "."} for part in parts) or path.endswith("/"):
            raise TryRepairProviderError("provider returned ambiguous patch path")
        if path in seen:
            raise TryRepairProviderError("provider returned duplicate patch path")
        seen.add(path)
        if (
            path.startswith("/")
            or ".." in parts
            or path in _DENIED_NAMES
            or any(part in _DENIED_COMPONENTS for part in parts)
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
    if host in {"127.0.0.1", "localhost", "::1"} or host.endswith(".workers.dev"):
        return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout)
    return urllib.request.urlopen(req, timeout=timeout)


def health() -> dict[str, Any]:
    url = os.environ.get("TRY_REPAIR_PROVIDER_URL", "").strip()
    token = os.environ.get("TRY_REPAIR_PROVIDER_TOKEN", "").strip()
    if not url or not token:
        raise TryRepairProviderError("TRY provider endpoint/token not configured")
    req = urllib.request.Request(
        url.rstrip("/") + "/healthz",
        headers={"Authorization": "Bearer " + token, "User-Agent": "AIOS-TRY-Repair/1.0"},
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
    if not isinstance(request_id, str) or not request_id.strip() or not isinstance(repository, str) or not repository.strip():
        raise TryRepairProviderError("invalid provider request identity")
    if not isinstance(sha, str) or len(sha) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in sha):
        raise TryRepairProviderError("invalid provider request identity")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
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
            "User-Agent": "AIOS-TRY-Repair/1.0",
        },
        method="POST",
    )
    last_error: TryRepairProviderError | None = None
    for retry_no in range(_PROVIDER_RETRY_ATTEMPTS):
        try:
            with _open(req, int(os.environ.get("TRY_REPAIR_PROVIDER_TIMEOUT", "120"))) as response:
                payload = json.loads(response.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:1000]
            except Exception:
                detail = ""
            last_error = TryRepairProviderError(
                f"provider request failed: HTTP {exc.code}: {detail or exc.reason}"
            )
            if exc.code == 429:
                raise last_error from exc
            if exc.code not in _RETRYABLE_HTTP or retry_no == _PROVIDER_RETRY_ATTEMPTS - 1:
                raise last_error from exc
            time.sleep(_PROVIDER_RETRY_BACKOFF[retry_no])
        except Exception as exc:
            raise TryRepairProviderError(f"provider request failed: {type(exc).__name__}: {exc}") from exc
    else:
        raise last_error or TryRepairProviderError("provider request failed: retry exhausted")
    payload = validate_proposal(payload)
    if payload.get("status") == "HOLD":
        return payload
    payload["request_id"] = request_id
    payload["base_sha"] = sha
    payload["attempt"] = int(attempt)
    return payload


__all__ = ["TryRepairProviderError", "health", "propose", "validate_proposal"]
