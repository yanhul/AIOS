#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from core.repair_planner import planner_from_env

MAX_SOURCE_FILES = 80
MAX_FILE_BYTES = 120_000
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

def main() -> int:
    sha = os.environ["AIOS_REPAIR_SHA"]
    run_id = os.environ["AIOS_REPAIR_RUN_ID"]
    log = Path(os.environ["AIOS_REPAIR_LOG"]).read_text(encoding="utf-8", errors="replace")[-80_000:]

    names = [
        p for p in git("ls-tree", "-r", "--name-only", sha).splitlines()
        if (p.startswith("core/") or p.startswith("scripts/"))
        and p.endswith(".py")
        and not p.startswith("tests/")
    ][:MAX_SOURCE_FILES]
    source = {p: show(sha, p) for p in names}
    source = {k: v for k, v in source.items() if v}

    class Tools:
        def inspect(self, path: str):
            return {"path": path, "content": source.get(path, ""), "found": path in source}

        def search(self, query: str):
            q = query.lower()
            hits = []
            for path, content in source.items():
                if q in content.lower():
                    hits.append(path)
            return {"query": query, "matches": hits[:20]}

    planner = planner_from_env(source=source)
    failure = {"run_id": int(run_id), "sha": sha, "ci_failure_log_tail": log}
    observations = []
    proposal = None

    for turn in range(6):
        nxt = planner.next_turn(failure=failure, observations=observations)
        for call in nxt.calls:
            if call.name == "inspect":
                result = Tools().inspect(str(call.args.get("path", "")))
                observations.append({"turn": turn, "tool": "inspect", "result": result})
            elif call.name == "search":
                result = Tools().search(str(call.args.get("query", "")))
                observations.append({"turn": turn, "tool": "search", "result": result})
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
                    "schema": 1,
                    "run_id": int(run_id),
                    "base_sha": sha,
                    "root_cause": str(call.args.get("root_cause", "")),
                    "proposed_fix": str(call.args.get("proposed_fix", "")),
                    "files": clean,
                }
                break
        if proposal:
            break

    if not proposal:
        raise SystemExit("planner exhausted without a patch proposal")
    Path("repair-proposal.json").write_text(json.dumps(proposal, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": "PROPOSAL_READY", "files": [x["path"] for x in proposal["files"]]}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
