#!/usr/bin/env python3
"""Daily AIOS ecosystem discovery.

Discovery/research only: it creates provenance-bearing candidate records and
never mutates AIOS authority, policy, gates, evidence rules, or source code.
Absorption is a separate governed decision.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.github.com"
DEFAULT_QUERIES = [
    "agent harness",
    "agent runtime",
    "durable agent",
    "agent research",
    "agent skills MCP",
    "AI agent orchestration",
]
INTEREST = {
    "durable", "evidence", "provenance", "verification", "runtime",
    "harness", "agent", "research", "mcp", "skills", "sandbox",
    "workflow", "checkpoint", "resume", "memory", "orchestration",
}


def _get(url: str, token: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {token}",
        "User-Agent": "yanhul-AIOS-daily-research",
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


def relevance(repo: dict) -> int:
    text = _norm(" ".join([
        repo.get("name", ""),
        repo.get("description", ""),
        " ".join(repo.get("topics", []) or []),
    ]))
    return sum(1 for k in INTEREST if k in text)


def discover(token: str, queries: list[str], per_query: int = 10) -> list[dict]:
    seen: set[str] = set()
    rows: list[dict] = []
    for query in queries:
        params = urllib.parse.urlencode({
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": str(per_query),
        })
        data = _get(f"{API}/search/repositories?{params}", token)
        for repo in data.get("items", []):
            full = repo.get("full_name", "")
            if not full or full in seen:
                continue
            seen.add(full)
            rows.append({
                "full_name": full,
                "html_url": repo.get("html_url", ""),
                "default_branch": repo.get("default_branch", ""),
                "description": repo.get("description", ""),
                "topics": repo.get("topics", []) or [],
                "stars": repo.get("stargazers_count", 0),
                "forks": repo.get("forks_count", 0),
                "updated_at": repo.get("updated_at", ""),
                "relevance": relevance(repo),
                "discovery_query": query,
            })
    rows.sort(key=lambda x: (-x["relevance"], -x["stars"], x["full_name"]))
    return rows


def research_metadata(token: str, candidates: list[dict], limit: int = 20) -> list[dict]:
    out = []
    for c in candidates[:limit]:
        repo = _get(f"{API}/repos/{c['full_name']}", token)
        readme_digest = None
        try:
            readme = _get(f"{API}/repos/{c['full_name']}/readme", token)
            content = readme.get("content", "")
            readme_digest = hashlib.sha256(content.encode()).hexdigest()
        except Exception:
            pass
        c = dict(c)
        c.update({
            "archived": bool(repo.get("archived", False)),
            "license": (repo.get("license") or {}).get("spdx_id"),
            "open_issues": repo.get("open_issues_count", 0),
            "source_repo_updated_at": repo.get("updated_at", ""),
            "source_default_branch_sha": (repo.get("default_branch") or None),
            "readme_digest": readme_digest,
            "research_status": "DISCOVERED_METADATA",
            "absorption_status": "PENDING_GOVERNED_REVIEW",
        })
        out.append(c)
    return out


def main() -> int:
    token = os.environ["GITHUB_TOKEN"]
    queries = [q.strip() for q in os.getenv("AIOS_DAILY_RESEARCH_QUERIES", "").split(";") if q.strip()]
    if not queries:
        queries = DEFAULT_QUERIES
    limit = int(os.getenv("AIOS_DAILY_RESEARCH_LIMIT", "20"))
    now = dt.datetime.now(dt.timezone.utc)
    rows = research_metadata(token, discover(token, queries), limit)

    payload = {
        "schema": "AIOS-DAILY-RESEARCH-V1",
        "generated_at": now.isoformat(),
        "research_date": now.date().isoformat(),
        "run_id": os.getenv("GITHUB_RUN_ID"),
        "queries": queries,
        "candidate_count": len(rows),
        "governance": {
            "mutates_authority": False,
            "mutates_policy": False,
            "mutates_evidence_rules": False,
            "auto_absorb": False,
            "absorption_requires_governed_review": True,
        },
        "candidates": rows,
    }

    latest = Path(os.getenv("AIOS_DAILY_RESEARCH_OUTPUT", "research/daily/latest.json"))
    latest.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    latest.write_text(encoded, encoding="utf-8")

    run_id = os.getenv("GITHUB_RUN_ID")
    if run_id:
        history = latest.parent / "history" / f"{now.date().isoformat()}-run-{run_id}.json"
        history.parent.mkdir(parents=True, exist_ok=True)
        history.write_text(encoded, encoding="utf-8")

    print(json.dumps({
        "AIOS_DAILY_RESEARCH": "PASS",
        "candidate_count": len(rows),
        "output": str(latest),
        "history_written": bool(run_id),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
