#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

from core.try_repair_provider import propose as try_propose, health as try_health, TryRepairProviderError

MAX_SOURCE_FILES = 120
MAX_FILE_BYTES = 120_000
MAX_EXTERNAL_BYTES = 100_000
DENIED = (".github/workflows/", ".aios/", "secrets/")
DENIED_NAMES = {".env", ".env.local", ".env.production", "credentials.json"}


def git(*args: str) -> str:
    p = subprocess.run(["git", *args], text=True, capture_output=True, check=True)
    return p.stdout


def show(sha: str, path: str) -> str:
    p = subprocess.run(["git", "show", f"{sha}:{path}"], text=True, capture_output=True, check=False)
    if p.returncode:
        return ""
    return p.stdout[:MAX_FILE_BYTES]


class Tools:
    def __init__(self, sha: str):
        self.sha = sha
        self.token = os.environ.get("GITHUB_TOKEN", "")

    def inspect(self, path: str):
        norm = path.replace("\\", "/")
        if norm.startswith("/") or ".." in Path(norm).parts:
            return {"path": path, "found": False, "error": "unsafe path"}
        content = show(self.sha, norm)
        return {"path": norm, "content": content, "found": bool(content)}

    def search(self, query: str):
        q = query.strip()
        if not q:
            return {"query": query, "local_matches": [], "external_matches": []}
        local_hits = []
        for path in git("ls-tree", "-r", "--name-only", self.sha).splitlines():
            if not (path.startswith("core/") or path.startswith("scripts/")):
                continue
            content = show(self.sha, path)
            if q.lower() in content.lower():
                local_hits.append(path)
            if len(local_hits) >= 30:
                break
        external = []
        if self.token:
            params = urllib.parse.urlencode({"q": q, "per_page": "8"})
            req = urllib.request.Request(
                f"https://api.github.com/search/code?{params}",
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2026-03-10",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                external = [
                    {
                        "name": item.get("name"),
                        "path": item.get("path"),
                        "repo": (item.get("repository") or {}).get("full_name"),
                        "ref": (item.get("repository") or {}).get("default_branch") or "",
                        "url": item.get("html_url"),
                    }
                    for item in payload.get("items", [])
                ]
            except Exception as exc:
                external = [{"error": str(exc)}]
        return {"query": query, "local_matches": local_hits, "external_matches": external}

    def inspect_external(self, repo: str, path: str, ref: str = ""):
        repo = repo.strip()
        path = path.lstrip("/")
        if not repo or repo.count("/") != 1 or not path or ".." in Path(path).parts:
            return {"found": False, "error": "unsafe external reference"}
        if not self.token:
            return {"found": False, "error": "external inspection requires GITHUB_TOKEN"}
        url = f"https://api.github.com/repos/{repo}/contents/{urllib.parse.quote(path, safe='/')}"
        if ref:
            url += "?" + urllib.parse.urlencode({"ref": ref})
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if payload.get("type") != "file" or not payload.get("content"):
                return {"repo": repo, "path": path, "ref": ref, "found": False, "error": "not a regular file"}
            content = base64.b64decode(payload["content"]).decode("utf-8", errors="replace")[:MAX_EXTERNAL_BYTES]
            return {
                "repo": repo, "path": path, "ref": ref, "found": True,
                "content": content, "sha": payload.get("sha"), "html_url": payload.get("html_url"),
            }
        except Exception as exc:
            return {"repo": repo, "path": path, "ref": ref, "found": False, "error": str(exc)}


def main() -> int:
    sha = os.environ["AIOS_REPAIR_SHA"]
    run_id = os.environ["AIOS_REPAIR_RUN_ID"]
    log = Path(os.environ["AIOS_REPAIR_LOG"]).read_text(encoding="utf-8", errors="replace")[-80_000:]
    names = [
        p for p in git("ls-tree", "-r", "--name-only", sha).splitlines()
        if (p.startswith("core/") or p.startswith("scripts/"))
        and p.endswith(".py") and not p.startswith("tests/")
    ][:MAX_SOURCE_FILES]
    source = {p: show(sha, p) for p in names}
    source = {k: v for k, v in source.items() if v}
    # Fail closed before asking the reasoning provider for a proposal.
    try:
        health = try_health()
        print("TRY_PROVIDER_READY", json.dumps(health, sort_keys=True))
    except TryRepairProviderError as exc:
        raise SystemExit(f"TRY_PROVIDER_BLOCKED: {exc}") from exc

    failure = {
        "run_id": int(run_id),
        "sha": sha,
        "attempt": int(os.environ.get("AIOS_REPAIR_ATTEMPT", "1")),
        "ci_failure_log_tail": log,
    }
    previous = os.environ.get("AIOS_REPAIR_PREVIOUS_RESULT")
    if previous and Path(previous).exists():
        failure["previous_repair_result"] = json.loads(Path(previous).read_text(encoding="utf-8"))

    request_id = f"aios-ci-repair:{run_id}:{failure['attempt']}"
    try:
        proposal = try_propose(
            request_id=request_id,
            repository=os.environ.get("GITHUB_REPOSITORY", "yanhul/AIOS"),
            sha=sha,
            attempt=failure["attempt"],
            failure=failure,
            source=source,
        )
    except TryRepairProviderError as exc:
        raise SystemExit(f"TRY_PROVIDER_BLOCKED: {exc}") from exc
    if proposal.get("status") == "HOLD":
        raise SystemExit(f"TRY_PROVIDER_HOLD: {proposal.get('reason', 'provider hold')}")

    Path("repair-proposal.json").write_text(json.dumps(proposal, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": "PROPOSAL_READY", "attempt": proposal["attempt"], "files": [x["path"] for x in proposal["files"]]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
