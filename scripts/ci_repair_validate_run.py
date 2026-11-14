#!/usr/bin/env python3
"""Fail-closed binding of a repair request to one real failed CI run."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request


ALLOWED_WORKFLOWS = {
    ".github/workflows/ci.yml",
    ".github/workflows/g4a-ci.yml",
}


def validate_run(payload: dict, *, repository: str, run_id: int,
                 expected_sha: str, expected_branch: str) -> None:
    if not isinstance(payload, dict):
        raise ValueError("run response is not an object")
    if payload.get("id") != run_id:
        raise ValueError("run ID mismatch")
    if (payload.get("repository") or {}).get("full_name", "").lower() != repository.lower():
        raise ValueError("run repository mismatch")
    if (payload.get("head_repository") or {}).get("full_name", "").lower() != repository.lower():
        raise ValueError("head repository mismatch (forks are not eligible)")
    if payload.get("status") != "completed" or payload.get("conclusion") != "failure":
        raise ValueError("source run is not a completed failure")
    if payload.get("head_sha") != expected_sha:
        raise ValueError("source run head SHA mismatch")
    if payload.get("head_branch") != expected_branch:
        raise ValueError("source run head branch mismatch")
    if expected_branch != "main" and not (expected_branch.startswith("aios/autorepair/") and len(expected_branch) > len("aios/autorepair/")):
        raise ValueError("source branch is outside the repair allowlist")
    if payload.get("path") not in ALLOWED_WORKFLOWS:
        raise ValueError("source workflow path is not an approved CI workflow")
    if payload.get("event") not in {"push", "pull_request", "workflow_dispatch"}:
        raise ValueError("source workflow event is not eligible")


def main() -> int:
    repository = os.environ["REPO"]
    run_id_text = os.environ["TRIGGER_RUN_ID"]
    expected_sha = os.environ["EXPECTED_SHA"]
    expected_branch = os.environ["EXPECTED_BRANCH"]
    token = os.environ["GH_TOKEN"]
    if not re.fullmatch(r"[0-9]+", run_id_text):
        raise SystemExit("BLOCKED: run_id must be decimal digits")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise SystemExit("BLOCKED: base_sha must be a full lowercase Git SHA")
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", expected_branch) or ".." in expected_branch.split("/"):
        raise SystemExit("BLOCKED: invalid source branch syntax")
    run_id = int(run_id_text)
    url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
        validate_run(payload, repository=repository, run_id=run_id,
                     expected_sha=expected_sha, expected_branch=expected_branch)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"BLOCKED: failed CI run binding validation: {exc}") from exc
    print(f"VERIFIED_CI_RUN_ID={run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
