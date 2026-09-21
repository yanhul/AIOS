"""Bounded GitHub ecosystem discovery for AIOS research intake.

Discovery is advisory. It emits source-backed records only; it never mutates
AIOS policy, source workloads, or promotion state.
"""
from __future__ import annotations
import hashlib, json, os, urllib.parse, urllib.request
from pathlib import Path

QUERIES = (
    "agent harness durable execution",
    "agent research framework autonomous experimentation",
    "agent memory provenance governance",
)
MAX_RESULTS = 5
OUT = Path(os.environ.get("AIOS_RESEARCH_OUT", "research/artifacts/daily-scan.json"))

def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept":"application/vnd.github+json",
                                               "User-Agent":"AIOS-daily-research"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)

def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def scan() -> dict:
    records = []
    for query in QUERIES:
        url = "https://api.github.com/search/repositories?" + urllib.parse.urlencode({
            "q": query, "sort": "updated", "order": "desc", "per_page": MAX_RESULTS})
        data = _get(url)
        for item in data.get("items", []):
            records.append({
                "source_ref": item.get("html_url",""),
                "repo": item.get("full_name",""),
                "ref": item.get("default_branch",""),
                "description": item.get("description") or "",
                "stars": item.get("stargazers_count",0),
                "updated_at": item.get("updated_at"),
                "query": query,
                "source_digest": _digest(json.dumps(item, sort_keys=True)),
            })
    unique = {r["source_ref"]: r for r in records if r["source_ref"]}
    result = {"schema_version": 1, "kind": "AIOS_DAILY_RESEARCH",
              "records": list(unique.values())}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    scan()
