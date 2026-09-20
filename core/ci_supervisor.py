"""Event/wake boundary for autonomous GitHub CI supervision.

The supervisor does not grant authority or modify repository state. It polls
GitHub for a PR head and emits one durable event when a new workflow run
reaches a terminal state. A higher-level worker consumes the event and invokes
the repair controller.
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping


class CISupervisorError(RuntimeError):
    pass


@dataclass(frozen=True)
class CIEvent:
    repository: str
    pull_request: int
    head_sha: str
    run_id: int
    workflow: str
    conclusion: str
    next_action: str


class DurableSupervisorState:
    def __init__(self, path: str):
        self.path = path

    def load(self) -> dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return {}

    def save(self, state: Mapping[str, Any]) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".ci-supervisor-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(dict(state), fh, sort_keys=True, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


class GitHubCIClient:
    def __init__(self, token: str | None = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            raise CISupervisorError("GITHUB_TOKEN is required")

    def get_json(self, path: str) -> Mapping[str, Any]:
        request = urllib.request.Request(
            "https://api.github.com" + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise CISupervisorError(f"GitHub request failed: {exc}") from exc


class CISupervisor:
    def __init__(self, client: GitHubCIClient, state: DurableSupervisorState):
        self.client = client
        self.state = state

    def poll(self, repository: str, pull_request: int) -> CIEvent | None:
        pr = self.client.get_json(f"/repos/{repository}/pulls/{pull_request}")
        head = pr.get("head") or {}
        head_sha = head.get("sha")
        if not isinstance(head_sha, str) or not head_sha:
            raise CISupervisorError("PR head SHA is missing")

        query = urllib.parse.urlencode({"head_sha": head_sha, "per_page": "20"})
        payload = self.client.get_json(f"/repos/{repository}/actions/runs?{query}")
        runs = payload.get("workflow_runs", [])
        if not isinstance(runs, list):
            raise CISupervisorError("workflow_runs is not a list")

        candidates = [
            r for r in runs
            if r.get("status") == "completed" and r.get("id") is not None
        ]
        if not candidates:
            return None

        run = max(candidates, key=lambda item: item.get("run_number", 0))
        run_id = int(run["id"])
        key = f"{repository}#{pull_request}:{head_sha}:{run_id}"
        state = self.state.load()
        if state.get("last_event_key") == key:
            return None

        conclusion = str(run.get("conclusion") or "unknown")
        next_action = "REPAIR" if conclusion != "success" else "VERIFY_MERGE"
        event = CIEvent(
            repository=repository,
            pull_request=pull_request,
            head_sha=head_sha,
            run_id=run_id,
            workflow=str(run.get("name") or "unknown"),
            conclusion=conclusion,
            next_action=next_action,
        )
        self.state.save({
            "last_event_key": key,
            "repository": repository,
            "pull_request": pull_request,
            "head_sha": head_sha,
            "run_id": run_id,
            "conclusion": conclusion,
            "next_action": next_action,
        })
        return event


__all__ = ["CIEvent", "CISupervisor", "CISupervisorError", "DurableSupervisorState", "GitHubCIClient"]
