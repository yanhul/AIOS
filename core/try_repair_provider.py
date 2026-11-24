"""Validation-only client helpers for the TRY-owned reasoning provider.

AIOS owns authority, mutation and verification. TRY owns the external model
credential. This module contains no Gemini endpoint or credential handling.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
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
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


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
    url = os.environ.get("TRY_REPAIR_WORKER_URL", "").strip()
    token = os.environ.get("TRY_PROVIDER_TOKEN", "").strip()
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


def _request_digest(body: Mapping[str, Any]) -> str:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def lookup_proposal(*, request_id: str, expected_request_digest: str | None = None) -> dict[str, Any] | None:
    """Read the TRY Durable Object operation record without starting a provider call.

    A 404 means the worker has no durable claim for this request ID. UNKNOWN is
    never converted into a retry permission. COMPLETED returns the cached,
    schema-validated proposal; FAILED remains terminal until AIOS reconciles it.
    """
    url = os.environ.get("TRY_REPAIR_WORKER_URL", "").strip()
    token = os.environ.get("TRY_PROVIDER_TOKEN", "").strip()
    if not url or not token:
        raise TryRepairProviderError("TRY provider endpoint/token not configured")
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise TryRepairProviderError("invalid provider request id")
    if expected_request_digest is not None and (
        not isinstance(expected_request_digest, str) or not _DIGEST.fullmatch(expected_request_digest)
    ):
        raise TryRepairProviderError("invalid expected provider request digest")
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/repair/proposal/" + request_id,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json",
                 "User-Agent": "AIOS-TRY-Repair/1.0"},
        method="GET",
    )
    try:
        with _open(req, int(os.environ.get("TRY_REPAIR_PROVIDER_TIMEOUT", "20"))) as response:
            status_code = getattr(response, "status", 200)
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise TryRepairProviderError(f"provider operation lookup failed: HTTP {exc.code}: {detail or exc.reason}") from exc
    except Exception as exc:
        raise TryRepairProviderError(f"provider operation lookup failed: {type(exc).__name__}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("request_id") != request_id:
        raise TryRepairProviderError("provider operation lookup identity mismatch")
    digest = payload.get("request_digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise TryRepairProviderError("provider operation lookup digest invalid")
    if expected_request_digest is not None and digest != expected_request_digest:
        raise TryRepairProviderError("provider operation lookup digest mismatch")
    state = payload.get("status")
    if state == "COMPLETED" and status_code == 200:
        proposal = validate_proposal(payload.get("proposal"))
        return {"status": state, "request_id": request_id, "request_digest": digest, "proposal": proposal}
    if state == "UNKNOWN" and status_code == 202:
        if payload.get("execution_state") != "IN_PROGRESS" or payload.get("retry_allowed") is not False:
            raise TryRepairProviderError("provider UNKNOWN operation has unsafe retry metadata")
        return {"status": state, "request_id": request_id, "request_digest": digest,
                "execution_state": "IN_PROGRESS", "retry_allowed": False}
    if state == "FAILED" and status_code == 200:
        if payload.get("retry_allowed") is not False:
            raise TryRepairProviderError("provider FAILED operation has unsafe retry metadata")
        return {"status": state, "request_id": request_id, "request_digest": digest,
                "failure_code": str(payload.get("failure_code") or "provider_terminal_failure"),
                "retry_allowed": False}
    raise TryRepairProviderError("provider operation lookup state/status invalid")


def _recover_proposal(operation: Mapping[str, Any], *, request_id: str, sha: str, attempt: int) -> dict[str, Any]:
    state = operation.get("status")
    if state == "COMPLETED":
        proposal = dict(operation["proposal"])
        proposal["request_id"] = request_id
        proposal["base_sha"] = sha
        proposal["attempt"] = int(attempt)
        return proposal
    if state == "UNKNOWN":
        raise TryRepairProviderError("provider operation UNKNOWN; refusing duplicate Gemini execution")
    if state == "FAILED":
        raise TryRepairProviderError("provider operation FAILED; explicit AIOS reconciliation required")
    raise TryRepairProviderError("provider operation state unsupported")


def propose(*, request_id: str, repository: str, sha: str, attempt: int,
            failure: Mapping[str, Any], source: Mapping[str, str]) -> dict[str, Any]:
    url = os.environ.get("TRY_REPAIR_WORKER_URL", "").strip()
    token = os.environ.get("TRY_PROVIDER_TOKEN", "")
    if not url or not token:
        raise TryRepairProviderError("TRY provider endpoint/token not configured")
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id) or not isinstance(repository, str) or not repository.strip():
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
    expected_request_digest = _request_digest(body)
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
            if exc.code in _RETRYABLE_HTTP or exc.code == 409:
                operation = lookup_proposal(request_id=request_id, expected_request_digest=expected_request_digest)
                if operation is not None:
                    payload = _recover_proposal(operation, request_id=request_id, sha=sha, attempt=attempt)
                    break
            if exc.code == 429:
                raise last_error from exc
            if exc.code not in _RETRYABLE_HTTP or retry_no == _PROVIDER_RETRY_ATTEMPTS - 1:
                raise last_error from exc
            time.sleep(_PROVIDER_RETRY_BACKOFF[retry_no])
        except Exception as exc:
            try:
                operation = lookup_proposal(request_id=request_id, expected_request_digest=expected_request_digest)
            except TryRepairProviderError as lookup_exc:
                raise lookup_exc from exc
            if operation is not None:
                payload = _recover_proposal(operation, request_id=request_id, sha=sha, attempt=attempt)
                break
            raise TryRepairProviderError(f"provider request failed: {type(exc).__name__}: {exc}") from exc
    else:
        raise last_error or TryRepairProviderError("provider request failed: retry exhausted")
    if isinstance(payload, dict) and payload.get("status") in {"UNKNOWN", "FAILED"}:
        state = payload.get("status")
        if state == "UNKNOWN":
            raise TryRepairProviderError("provider operation UNKNOWN; refusing duplicate Gemini execution")
        raise TryRepairProviderError("provider operation FAILED; explicit AIOS reconciliation required")
    payload = validate_proposal(payload)
    if payload.get("status") == "HOLD":
        return payload
    payload["request_id"] = request_id
    payload["base_sha"] = sha
    payload["attempt"] = int(attempt)
    return payload


__all__ = ["TryRepairProviderError", "health", "lookup_proposal", "propose", "validate_proposal"]
