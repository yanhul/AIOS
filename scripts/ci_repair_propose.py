#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

from core.repair_planner import planner_from_env

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
    planner = planner_from_env(source=source)
    failure = {
        "run_id": int(run_id),
        "sha": sha,
        "attempt": int(os.environ.get("AIOS_REPAIR_ATTEMPT", "1")),
        "ci_failure_log_tail": log,
    }
    previous = os.environ.get("AIOS_REPAIR_PREVIOUS_RESULT")
    if previous and Path(previous).exists():
        failure["previous_repair_result"] = json.loads(Path(previous).read_text(encoding="utf-8"))
    observations = []
    proposal = None
    tools = Tools(sha)
    for turn in range(6):
        nxt = planner.next_turn(failure=failure, observations=observations)
        for call in nxt.calls:
            if call.name == "inspect":
                observations.append({"turn": turn, "tool": "inspect", "result": tools.inspect(str(call.args.get("path", "")))})
            elif call.name == "search":
                observations.append({"turn": turn, "tool": "search", "result": tools.search(str(call.args.get("query", "")))})
            elif call.name == "inspect_external":
                observations.append({
                    "turn": turn, "tool": "inspect_external",
                    "result": tools.inspect_external(
                        str(call.args.get("repo", "")),
                        str(call.args.get("path", "")),
                        str(call.args.get("ref", "")),
                    ),
                })
            elif call.name == "patch":
                files = call.args.get("files")
                if not isinstance(files, list) or not files:
                    raise SystemExit("invalid empty patch")
                clean = []
                for item in files:
                    path, content = item.get("path"), item.get("content")
                    if not isinstance(path, str) or not isinstance(content, str):
                        raise SystemExit("invalid patch file")
                    norm = path.replace("\\", "/")
                    if norm.startswith("../") or "/../" in norm or norm.startswith("/") or norm.startswith(DENIED):
                        raise SystemExit(f"protected/unsafe patch path: {path}")
                    if norm in DENIED_NAMES or norm.startswith("tests/"):
                        raise SystemExit(f"repair policy forbids patch path: {path}")
                    clean.append({"path": norm, "content": content})
                proposal = {
                    "schema": 2, "attempt": int(failure["attempt"]), "run_id": int(run_id),
                    "base_sha": sha, "root_cause": str(call.args.get("root_cause", "")),
                    "proposed_fix": str(call.args.get("proposed_fix", "")), "files": clean,
                }
                break
        if proposal:
            break
    if not proposal:
        raise SystemExit("planner exhausted without a patch proposal")
    Path("repair-proposal.json").write_text(json.dumps(proposal, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": "PROPOSAL_READY", "attempt": proposal["attempt"], "files": [x["path"] for x in proposal["files"]]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
