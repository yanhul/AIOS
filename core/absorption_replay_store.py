"""Durable one-time absorption permit consumption using GitHub Contents CAS.

The dedicated ledger branch is append-only. GitHub's contents API requires the
current blob SHA for updates; concurrent consumers racing on the same SHA cannot
both commit. Any API error or conflict is DENY. No local cache is authoritative.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

from core.mutation import canonical_json

LEDGER_REPOSITORY = "yanhul/AIOS-replay-ledger"
LEDGER_BRANCH = "main"
LEDGER_PATH = ".aios/absorption-consumed-permits.json"
MAX_ENTRIES = 10000


class ReplayStoreError(RuntimeError):
    """Replay state could not be safely read or atomically updated."""


def _api_request(url: str, *, token: str, method: str = "GET",
                 payload: Mapping[str, Any] | None = None) -> tuple[int, bytes]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AIOS-absorption-replay-store",
    }
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception as exc:
        raise ReplayStoreError("replay ledger API unavailable; DENY") from exc


def consume_permit_once(*, permit: Mapping[str, Any], repository: str,
                        token: str | None = None, branch: str = LEDGER_BRANCH,
                        now: int | None = None) -> str:
    """Atomically record a permit exactly once; return its stable permit ID."""
    credential = token or os.environ.get("AIOS_REPLAY_LEDGER_TOKEN", "")
    if not credential:
        raise ReplayStoreError("AIOS_REPLAY_LEDGER_TOKEN with contents:write is required; DENY")
    if not isinstance(repository, str) or repository.count("/") != 1:
        raise ReplayStoreError("repository identity malformed; DENY")
    if not isinstance(branch, str) or not branch or "/" in branch:
        raise ReplayStoreError("replay ledger branch malformed; DENY")
    if not isinstance(permit, Mapping) or not isinstance(permit.get("signature"), str):
        raise ReplayStoreError("signed permit missing; DENY")

    permit_id = hashlib.sha256(canonical_json(dict(permit)).encode("utf-8")).hexdigest()
    base = "https://api.github.com/repos/" + repository
    encoded_path = urllib.parse.quote(LEDGER_PATH, safe="/")
    get_url = f"{base}/contents/{encoded_path}?ref={urllib.parse.quote(branch, safe='')}"
    status, raw = _api_request(get_url, token=credential)
    if status == 404:
        ledger, blob_sha = {"schema_version": 1, "consumed": {}}, None
    elif status == 200:
        try:
            response = json.loads(raw.decode("utf-8"))
            blob_sha = response["sha"]
            decoded = base64.b64decode(response["content"], validate=False)
            ledger = json.loads(decoded.decode("utf-8"))
        except Exception as exc:
            raise ReplayStoreError("replay ledger malformed or unreadable; DENY") from exc
    else:
        raise ReplayStoreError(f"replay ledger read failed (HTTP {status}); DENY")

    if (not isinstance(ledger, dict) or ledger.get("schema_version") != 1 or
            not isinstance(ledger.get("consumed"), dict)):
        raise ReplayStoreError("replay ledger schema invalid; DENY")
    consumed = ledger["consumed"]
    if permit_id in consumed:
        raise ReplayStoreError("permit already consumed; replay denied")
    if len(consumed) >= MAX_ENTRIES:
        raise ReplayStoreError("replay ledger capacity reached; DENY")

    target_id = permit.get("target_apply_run_id")
    if not isinstance(target_id, str) or not target_id:
        raise ReplayStoreError("permit target apply run missing; DENY")
    consumed[permit_id] = {
        "consumed_at": int(time.time()) if now is None else int(now),
        "target_apply_run_id": target_id,
    }
    body = canonical_json(ledger).encode("utf-8")
    payload = {
        "message": "security: consume absorption permit " + permit_id,
        "content": base64.b64encode(body).decode("ascii"),
        "branch": branch,
    }
    if blob_sha:
        payload["sha"] = blob_sha
    put_url = f"{base}/contents/{encoded_path}"
    put_status, _ = _api_request(put_url, token=credential, method="PUT", payload=payload)
    if put_status not in (200, 201):
        # In particular, HTTP 409/422 means a concurrent writer won the CAS.
        # Never retry this permit: the caller must stop and investigate.
        raise ReplayStoreError(f"atomic replay-ledger write failed (HTTP {put_status}); DENY")
    return permit_id


__all__ = ["ReplayStoreError", "consume_permit_once", "LEDGER_REPOSITORY", "LEDGER_BRANCH", "LEDGER_PATH"]
