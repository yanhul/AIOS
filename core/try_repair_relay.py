"""GitHub Actions relay from AIOS to the TRY-owned reasoning workflow.

No Gemini credential or model endpoint is known here. AIOS authenticates only to
the TRY GitHub repository with a separate bridge token, dispatches a bounded
request, waits for the TRY workflow, and downloads its proposal artifact.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

API = "https://api.github.com"
TRY_REPO = "yanhul/try"
TRY_WORKFLOW = "aios-repair-propose.yml"
MAX_INPUT_BYTES = 60_000
POLL_SECONDS = 5
MAX_WAIT_SECONDS = 600


class TryRelayError(RuntimeError):
    pass


def _request(method: str, path: str, token: str, body: dict[str, Any] | None = None) -> Any:
    data = None if body is None else json.dumps(body, sort_keys=True).encode("utf-8")
    req = urllib.request.Request(
        API + path,
        data=data,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise TryRelayError(f"GitHub API {exc.code}: {detail}") from exc
    except Exception as exc:
        raise TryRelayError(f"GitHub API transport failed: {type(exc).__name__}: {exc}") from exc


def _download(path: str, token: str) -> bytes:
    req = urllib.request.Request(
        API + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.read()
    except Exception as exc:
        raise TryRelayError(f"artifact download failed: {type(exc).__name__}: {exc}") from exc


def propose(*, request_id: str, repository: str, sha: str, attempt: int,
            failure: dict[str, Any], source: dict[str, str]) -> dict[str, Any]:
    token = os.environ.get("TRY_GITHUB_TOKEN", "").strip()
    if not token:
        raise TryRelayError("TRY_GITHUB_TOKEN is not configured")
    if len(sha) != 40 or not request_id:
        raise TryRelayError("invalid relay identity")

    request = {
        "request_id": request_id,
        "repository": repository,
        "sha": sha,
        "attempt": int(attempt),
        "failure": failure,
        "source_snapshot": source,
    }
    encoded = json.dumps(request, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise TryRelayError("relay request exceeds GitHub workflow input limit")

    artifact_name = "aios-repair-" + request_id.replace(":", "-").replace("/", "-")
    dispatched = _request(
        "POST",
        f"/repos/{TRY_REPO}/actions/workflows/{TRY_WORKFLOW}/dispatches",
        token,
        {
            "ref": "main",
            "inputs": {"request": encoded, "artifact_name": artifact_name},
            "return_run_details": True,
        },
    )
    try_run_id = int(dispatched["workflow_run_id"])
    print(f"TRY_WORKFLOW_DISPATCHED run_id={try_run_id}")

    deadline = time.monotonic() + MAX_WAIT_SECONDS
    run: dict[str, Any]
    while True:
        run = _request("GET", f"/repos/{TRY_REPO}/actions/runs/{try_run_id}", token)
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status == "completed":
            if conclusion != "success":
                raise TryRelayError(f"TRY workflow failed: {conclusion}")
            break
        if time.monotonic() >= deadline:
            raise TryRelayError("TRY workflow timed out")
        time.sleep(POLL_SECONDS)

    artifacts = _request(
        "GET", f"/repos/{TRY_REPO}/actions/runs/{try_run_id}/artifacts?per_page=100", token
    ).get("artifacts", [])
    matches = [
        a for a in artifacts
        if a.get("name") == artifact_name and not a.get("expired")
    ]
    if len(matches) != 1:
        raise TryRelayError(f"expected exactly one TRY proposal artifact, found {len(matches)}")
    artifact = matches[0]
    archive = _download(
        f"/repos/{TRY_REPO}/actions/artifacts/{int(artifact['id'])}/zip", token
    )
    expected_digest = str(artifact.get("digest") or "")
    actual_digest = "sha256:" + hashlib.sha256(archive).hexdigest()
    if expected_digest and expected_digest != actual_digest:
        raise TryRelayError("TRY artifact digest mismatch")

    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            names = [n for n in zf.namelist() if n == "repair-proposal.json"]
            if names != ["repair-proposal.json"]:
                raise TryRelayError("TRY artifact does not contain exactly repair-proposal.json")
            proposal = json.loads(zf.read("repair-proposal.json").decode("utf-8"))
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as exc:
        raise TryRelayError(f"invalid TRY proposal artifact: {type(exc).__name__}") from exc

    if not isinstance(proposal, dict):
        raise TryRelayError("TRY proposal is not an object")
    if proposal.get("request_id") != request_id:
        raise TryRelayError("TRY proposal request_id mismatch")
    if proposal.get("base_sha") != sha:
        raise TryRelayError("TRY proposal base_sha mismatch")
    if int(proposal.get("attempt", -1)) != int(attempt):
        raise TryRelayError("TRY proposal attempt mismatch")
    if proposal.get("schema") != 2 or not isinstance(proposal.get("files"), list) or not proposal["files"]:
        raise TryRelayError("TRY proposal schema invalid")
    return proposal
