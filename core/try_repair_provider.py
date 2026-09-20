"""Client for the TRY-owned reasoning provider.

AIOS owns authority, mutation and verification. TRY owns the external model
credential. This client transports bounded evidence and treats the response
as untrusted proposal data.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Mapping


class TryRepairProviderError(RuntimeError):
    pass


def propose(*, request_id: str, repository: str, sha: str, attempt: int,
            failure: Mapping[str, Any], source: Mapping[str, str]) -> dict[str, Any]:
    url = os.environ.get("TRY_REPAIR_PROVIDER_URL", "").strip()
    token = os.environ.get("TRY_REPAIR_PROVIDER_TOKEN", "")
    if not url:
        raise TryRepairProviderError("TRY_REPAIR_PROVIDER_URL is not configured")
    if not token:
        raise TryRepairProviderError("TRY_REPAIR_PROVIDER_TOKEN is not configured")
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
        with urllib.request.urlopen(req, timeout=int(os.environ.get("TRY_REPAIR_PROVIDER_TIMEOUT", "120"))) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise TryRepairProviderError(f"provider request failed: {type(exc).__name__}: {exc}") from exc
    if not isinstance(payload, dict):
        raise TryRepairProviderError("provider response is not an object")
    if payload.get("status") == "HOLD":
        return {"status": "HOLD", "reason": str(payload.get("reason") or "provider_hold")}
    if payload.get("schema") != 2 or not isinstance(payload.get("files"), list) or not payload["files"]:
        raise TryRepairProviderError("provider returned invalid proposal schema")
    for item in payload["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("content"), str):
            raise TryRepairProviderError("provider returned invalid patch file")
    return payload


__all__ = ["TryRepairProviderError", "propose"]
