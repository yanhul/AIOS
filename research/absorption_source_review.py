"""Collect source-review evidence from an explicitly approved manifest.

This module never decides that a candidate is safe. It only materializes a review
that already has an explicit ACCEPTED decision, checks the immutable Git commit,
fetches the exact reviewed files at that commit, hashes their bytes, and validates
the AIOS implementation/test and authority-receipt references. Missing or invalid
review input remains BLOCKED.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = Path(os.environ.get("AIOS_ABSORPTION_EXECUTOR_OUT", "research/artifacts/absorption-executor.json"))
MANIFEST = Path(os.environ.get("AIOS_ABSORPTION_SOURCE_REVIEW_MANIFEST", "research/source_review_manifest.json"))
OUT = Path(os.environ.get("AIOS_ABSORPTION_SOURCE_REVIEW_OUT", "research/artifacts/absorption-source-review.json"))
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")

def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _digest_json(value) -> str:
    return _digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))

def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "AIOS-candidate-source-review",
    })
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read()

def _repo(source_ref: str):
    parsed = urllib.parse.urlparse(source_ref)
    parts = parsed.path.strip("/").split("/")
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or len(parts) < 2:
        raise ValueError("source_ref must be an https://github.com/owner/repo URL")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        raise ValueError("source_ref has no owner/repository")
    return owner, repo

def _local_refs(refs, *, tests=False):
    if not isinstance(refs, list) or not refs:
        raise ValueError("implementation_refs and candidate_test_refs must be non-empty lists")
    for ref in refs:
        if not isinstance(ref, str) or not ref.strip():
            raise ValueError("repository references must be non-empty relative file paths")
        path = Path(ref)
        try:
            resolved = (ROOT / path).resolve()
            resolved.relative_to(ROOT.resolve())
        except (ValueError, OSError):
            raise ValueError(f"repository reference escapes AIOS root: {ref}")
        if path.is_absolute() or ".." in path.parts or not resolved.is_file():
            raise ValueError(f"repository reference is not an existing safe file: {ref}")
        if tests and ("tests" not in path.parts or path.suffix != ".py"):
            raise ValueError(f"candidate test must be a Python file under tests/: {ref}")

def _review_one(record, manifest_entry, fetch=_get):
    if not isinstance(manifest_entry, dict):
        raise ValueError("review manifest entry must be an object")
    required = ("source_commit", "reviewer", "reviewed_at", "review_decision",
                "reviewed_files", "implementation_refs", "candidate_test_refs",
                "authority_receipt_lineage", "log_digest")
    missing = [key for key in required if not manifest_entry.get(key)]
    if missing:
        raise ValueError("review manifest missing: " + ", ".join(missing))
    if manifest_entry["review_decision"] != "ACCEPTED":
        raise ValueError("review decision is not ACCEPTED")
    commit = str(manifest_entry["source_commit"]).lower()
    if not SHA40.fullmatch(commit):
        raise ValueError("source_commit must be a full immutable Git SHA")
    if not SHA64.fullmatch(str(manifest_entry["log_digest"]).lower()):
        raise ValueError("log_digest must be SHA-256")
    if manifest_entry.get("candidate_primitive") != (record.get("adaptation") or {}).get("primitive"):
        raise ValueError("candidate_primitive does not match the scanned candidate")
    _local_refs(manifest_entry["implementation_refs"])
    _local_refs(manifest_entry["candidate_test_refs"], tests=True)
    lineage = manifest_entry["authority_receipt_lineage"]
    if not isinstance(lineage, dict) or not all(lineage.get(k) for k in
            ("effect_id", "attempt_id", "receipt_id", "evidence_digest")):
        raise ValueError("authority receipt lineage must bind effect, attempt, receipt, evidence")
    if not SHA64.fullmatch(str(lineage.get("evidence_digest", "")).lower()):
        raise ValueError("authority receipt evidence_digest must be SHA-256")
    paths = manifest_entry["reviewed_files"]
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p and ".." not in Path(p).parts and not Path(p).is_absolute() for p in paths):
        raise ValueError("reviewed_files must be a non-empty list of safe repository-relative paths")
    owner, repo = _repo(record.get("source_ref", ""))
    api = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit}"
    commit_info = json.loads(fetch(api).decode("utf-8"))
    if str(commit_info.get("sha", "")).lower() != commit:
        raise ValueError("GitHub commit API did not confirm the immutable source commit")
    files = []
    for path in sorted(set(paths)):
        encoded = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{encoded}"
        data = fetch(url)
        files.append({"path": path, "sha256": _digest_bytes(data)})
    source_code_digest = _digest_json(files)
    review = {
        "source_commit": commit, "reviewed_files": files, "source_code_digest": source_code_digest,
        "candidate_primitive": manifest_entry["candidate_primitive"],
        "implementation_refs": manifest_entry["implementation_refs"],
        "candidate_test_refs": manifest_entry["candidate_test_refs"],
        "conformance_run_id": record.get("run_id"),
        "log_digest": str(manifest_entry["log_digest"]).lower(),
        "authority_receipt_lineage": lineage, "reviewer": manifest_entry["reviewer"],
        "review_decision": "ACCEPTED", "reviewed_at": manifest_entry["reviewed_at"],
    }
    return review

def collect(executor: dict, manifest: dict, *, fetch=_get):
    reviews = manifest.get("reviews", [])
    if not isinstance(reviews, list):
        raise ValueError("source review manifest reviews must be a list")
    by_id = {}
    for entry in reviews:
        cid = entry.get("candidate_id") if isinstance(entry, dict) else None
        if not cid or cid in by_id:
            raise ValueError("source review manifest has missing or duplicate candidate_id")
        by_id[cid] = entry
    records = []
    statuses = []
    for original in executor.get("records", []):
        record = dict(original)
        cid = record.get("candidate_id")
        entry = by_id.get(cid)
        if not entry:
            statuses.append({"candidate_id": cid, "status": "BLOCKED", "reason": "no explicit source-review manifest entry"})
        else:
            try:
                record["source_review"] = _review_one(record, entry, fetch=fetch)
                statuses.append({"candidate_id": cid, "status": "REVIEW_EVIDENCE_COLLECTED",
                                 "source_commit": record["source_review"]["source_commit"],
                                 "source_code_digest": record["source_review"]["source_code_digest"]})
            except Exception as exc:
                record.pop("source_review", None)
                statuses.append({"candidate_id": cid, "status": "BLOCKED", "reason": f"{type(exc).__name__}: {exc}"})
        records.append(record)
    unknown = sorted(set(by_id) - {r.get("candidate_id") for r in executor.get("records", [])})
    for cid in unknown:
        statuses.append({"candidate_id": cid, "status": "BLOCKED", "reason": "review manifest candidate is absent from current executor run"})
    enriched = dict(executor)
    enriched["records"] = records
    executor_path = Path(os.environ.get("AIOS_ABSORPTION_EXECUTOR_OUT", str(EXECUTOR)))
    executor_path.parent.mkdir(parents=True, exist_ok=True)
    executor_path.write_text(json.dumps(enriched, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = {
        "schema_version": 1, "kind": "AIOS_ABSORPTION_SOURCE_REVIEW_COLLECTION",
        "run_id": executor.get("run_id"), "candidate_count": len(records),
        "review_evidence_count": sum(x["status"] == "REVIEW_EVIDENCE_COLLECTED" for x in statuses),
        "blocked_count": sum(x["status"] == "BLOCKED" for x in statuses),
        "records": statuses,
        "overall": "PASS" if records and all(x["status"] == "REVIEW_EVIDENCE_COLLECTED" for x in statuses) else "BLOCKED",
        "source_mutation": False, "external_code_execution": False,
    }
    out = Path(os.environ.get("AIOS_ABSORPTION_SOURCE_REVIEW_OUT", str(OUT)))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    executor_path = Path(os.environ.get("AIOS_ABSORPTION_EXECUTOR_OUT", str(EXECUTOR)))
    manifest_path = Path(os.environ.get("AIOS_ABSORPTION_SOURCE_REVIEW_MANIFEST", str(MANIFEST)))
    executor = json.loads(executor_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"reviews": []}
    result = collect(executor, manifest)
    print(json.dumps(result, indent=2))
    # Missing reviews are expected holds in an ecosystem scan, not proof of absorption.
    raise SystemExit(0)
