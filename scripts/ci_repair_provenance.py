#!/usr/bin/env python3
"""Candidate provenance for autonomous repair commits.

``statement``: in the publish job, after the candidate commit exists locally, write a
provenance statement bound to the exact commit/tree/parent and the reconciled AIOS
evidence, plus a git bundle carrying the commit. The statement is then signed with a
GitHub (Sigstore) artifact attestation by the workflow.

``verify``: in a separate job, before the candidate is pushed or opened for review,
fail closed unless the attestation was issued by this repository's repair workflow for
this run and the bundled commit is exactly the reconciled proposal patch on the base.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from core.repair_reconcile import patch_digest

KIND = "AIOS_REPAIR_CANDIDATE_PROVENANCE"
WORKFLOW_PATH = ".github/workflows/ci-autonomous-repair.yml"
FORBIDDEN_PREFIXES = (".github/", ".git/", ".aios/", "tests/", "test/", "secrets/")


def candidate_branch(source_run_id, repair_run_id) -> str:
    """One candidate branch per repair run; never reused across runs."""
    source, repair = str(source_run_id), str(repair_run_id)
    if not (source.isdigit() and repair.isdigit()):
        raise SystemExit("BLOCKED: source CI run and repair run IDs must be numeric")
    return f"aios/autorepair/{int(source)}-{int(repair)}"


def git(*args: str, cwd: str | Path = ".") -> str:
    return subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=True).stdout.strip()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(obj) -> str:
    return "sha256:" + _sha256_bytes(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _commit_facts(commit: str, cwd: str | Path = ".") -> dict:
    parents = git("show", "-s", "--format=%P", commit, cwd=cwd).split()
    paths = sorted(p for p in git("diff-tree", "--no-commit-id", "--name-only", "-r", commit, cwd=cwd).splitlines() if p)
    files = {}
    for path in paths:
        blob = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=cwd, capture_output=True, check=True).stdout
        files[path] = _sha256_bytes(blob)
    commit = git("rev-parse", commit, cwd=cwd)
    return {"commit": commit, "tree": git("show", "-s", "--format=%T", commit, cwd=cwd),
            "parents": parents, "files": files,
            "message": git("show", "-s", "--format=%B", commit, cwd=cwd)}


def _final_files(proposals) -> dict[str, str]:
    final: dict[str, str] = {}
    for proposal in sorted(proposals, key=lambda p: int(p["attempt"])):
        for item in proposal["files"]:
            final[item["path"]] = item["content"]
    return final


def _load_proposals(directory: Path, pass_attempt: int) -> list[dict]:
    proposals = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("repair-proposal-*.json"))]
    proposals = sorted((p for p in proposals if int(p.get("attempt", 0)) <= pass_attempt), key=lambda p: int(p["attempt"]))
    if [int(p["attempt"]) for p in proposals] != list(range(1, pass_attempt + 1)):
        raise SystemExit("BLOCKED: proposals are not a contiguous sequence for the PASS attempt")
    return proposals


def statement(out_dir: Path) -> dict:
    env = os.environ
    result = json.loads(Path(env["AIOS_REPAIR_RESULT_FILE"]).read_text(encoding="utf-8"))
    recon = result["reconciliation"]
    if result.get("status") != "REPAIR_E2E_PASS" or recon.get("status") != "RECONCILED":
        raise SystemExit("BLOCKED: provenance requires a reconciled REPAIR_E2E_PASS result")
    facts = _commit_facts("HEAD")
    body = {
        "schema": 1, "kind": KIND,
        "repository": env["GITHUB_REPOSITORY"],
        "source_run_id": int(env["AIOS_REPAIR_RUN_ID"]),
        "source_branch": env["AIOS_REPAIR_SOURCE_BRANCH"],
        "candidate_branch": git("branch", "--show-current"),
        "base_sha": env["AIOS_REPAIR_SHA"],
        "repair_run_id": int(env["GITHUB_RUN_ID"]),
        "repair_run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
        "workflow_ref": env["GITHUB_WORKFLOW_REF"],
        "workflow_sha": env["GITHUB_SHA"],
        "pass_attempt": int(env["AIOS_REPAIR_PASS_ATTEMPT"]),
        "commit": facts["commit"], "tree": facts["tree"], "parents": facts["parents"], "files": facts["files"],
        "patch_digest": recon["patch_digest"], "test_digest": recon["test_digest"],
        "contract_id": recon["contract_id"], "permit_id": recon["permit_id"],
        "receipt_ids": [e["receipt_id"] for e in recon["effects"]],
        "reconciliation_digest": _digest(recon),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "candidate-provenance.json").write_text(json.dumps(body, indent=2, sort_keys=True), encoding="utf-8")
    git("bundle", "create", str(out_dir / "candidate.bundle"), f"{env['AIOS_REPAIR_SHA']}..HEAD")
    return body


def verify_attestation(att: list, prov: dict) -> list[str]:
    """Check `gh attestation verify --format json` output against the statement."""
    errors = []
    if not isinstance(att, list) or not att:
        return ["no verified attestation"]
    repo_url = f"https://github.com/{prov['repository']}"
    run_prefix = f"{repo_url}/actions/runs/{prov['repair_run_id']}/attempts/"
    ok = False
    for item in att:
        cert = item.get("verificationResult", {}).get("signature", {}).get("certificate", {})
        if (cert.get("sourceRepositoryURI") == repo_url
                and cert.get("sourceRepositoryDigest") == prov["workflow_sha"]
                and str(cert.get("runInvocationURI", "")).startswith(run_prefix)
                and str(cert.get("buildSignerURI", "")).startswith(f"{repo_url}/{WORKFLOW_PATH}@")
                and cert.get("runnerEnvironment") == "github-hosted"):
            ok = True
    if not ok:
        errors.append("attestation is not from this repository's repair workflow run/commit")
    return errors


def verify(statement_path: Path, bundle: Path, attestation_json: Path, proposals_dir: Path,
           result_path: Path, cwd: str | Path = ".") -> dict:
    prov = json.loads(statement_path.read_text(encoding="utf-8"))
    result = json.loads(result_path.read_text(encoding="utf-8"))
    env = os.environ
    errors = verify_attestation(json.loads(attestation_json.read_text(encoding="utf-8")), prov)
    expect = {"kind": KIND, "schema": 1, "repository": env.get("GITHUB_REPOSITORY"),
              "repair_run_id": int(env.get("GITHUB_RUN_ID", 0)), "workflow_sha": env.get("GITHUB_SHA"),
              "base_sha": env.get("AIOS_REPAIR_SHA"), "source_run_id": int(env.get("AIOS_REPAIR_RUN_ID", 0)),
              "pass_attempt": int(env.get("AIOS_REPAIR_PASS_ATTEMPT", 0))}
    errors += [f"statement {k} mismatch" for k, v in expect.items() if prov.get(k) != v]
    if prov.get("candidate_branch") != candidate_branch(prov.get("source_run_id"), prov.get("repair_run_id")):
        errors.append("candidate branch is not aios/autorepair/<source-ci-run>-<repair-run>")

    git("fetch", "-q", "--no-tags", str(bundle), f"+HEAD:refs/aios/candidate", cwd=cwd)
    facts = _commit_facts("refs/aios/candidate", cwd=cwd)
    for key in ("commit", "tree", "parents", "files"):
        if facts[key] != prov.get(key):
            errors.append(f"bundled commit {key} != attested statement")
    if facts["parents"] != [prov.get("base_sha")]:
        errors.append("candidate commit is not a single-parent child of the failed base")
    if f"AIOS-Repair-Run: {prov.get('repair_run_id')}" not in facts["message"]:
        errors.append("candidate commit lacks AIOS-Repair-Run trailer for this run")

    proposals = _load_proposals(proposals_dir, int(prov.get("pass_attempt", 0)))
    final = _final_files(proposals)
    expected_files = {p: _sha256_bytes(c.encode("utf-8")) for p, c in final.items()}
    if facts["files"] != expected_files:
        errors.append("candidate commit content != cumulative proposal files")
    bad = [p for p in facts["files"] if p.startswith(FORBIDDEN_PREFIXES) or "/../" in f"/{p}/"]
    if bad:
        errors.append(f"candidate touches protected paths: {bad}")
    recon = result.get("reconciliation") or {}
    computed_patch = patch_digest([{"path": p, "content": c} for p, c in sorted(final.items())])
    if not (computed_patch == recon.get("patch_digest") == prov.get("patch_digest")):
        errors.append("patch digest mismatch between proposals, reconciliation and statement")
    if _digest(recon) != prov.get("reconciliation_digest") or recon.get("status") != "RECONCILED":
        errors.append("reconciliation record does not match attested digest")
    if errors:
        raise SystemExit("BLOCKED: candidate provenance verification failed: " + "; ".join(errors))
    return {"status": "PROVENANCE_VERIFIED", "commit": facts["commit"], "branch": prov["candidate_branch"],
            "statement_digest": "sha256:" + _sha256_bytes(statement_path.read_bytes())}



def validate_submission_base(prov: dict, current_base_sha: str, current_base_tree: str,
                             candidate_tree: str) -> dict:
    """Fail closed unless the submission target is still the attested base and non-no-op."""
    attested_base_sha = prov.get("base_sha")
    if not isinstance(attested_base_sha, str) or len(attested_base_sha) != 40:
        raise SystemExit("BLOCKED: INVALID_ATTESTED_BASE_SHA")
    if not isinstance(current_base_sha, str) or len(current_base_sha) != 40:
        raise SystemExit("BLOCKED: BASE_REF_UNRESOLVED")
    if not isinstance(current_base_tree, str) or len(current_base_tree) != 40:
        raise SystemExit("BLOCKED: BASE_TREE_UNRESOLVED")
    if not isinstance(candidate_tree, str) or len(candidate_tree) != 40:
        raise SystemExit("BLOCKED: CANDIDATE_TREE_UNRESOLVED")
    if current_base_sha != attested_base_sha:
        raise SystemExit(
            f"BLOCKED: BASE_MOVED attested={attested_base_sha} current={current_base_sha}"
        )
    if current_base_tree == candidate_tree:
        raise SystemExit(
            f"BLOCKED: NO_OP base_tree={current_base_tree} candidate_tree={candidate_tree}"
        )
    return {"status": "SUBMISSION_BASE_VERIFIED", "base_sha": current_base_sha,
            "base_tree": current_base_tree, "candidate_tree": candidate_tree}


def submission_check(statement_path: Path, current_base_sha: str,
                     current_base_tree: str, candidate_tree: str) -> dict:
    prov = json.loads(statement_path.read_text(encoding="utf-8"))
    return validate_submission_base(prov, current_base_sha, current_base_tree, candidate_tree)


def main(argv: list[str]) -> int:
    if argv[:1] == ["statement"]:
        print(json.dumps(statement(Path(argv[1])), sort_keys=True))
    elif argv[:1] == ["verify"]:
        print(json.dumps(verify(*(Path(a) for a in argv[1:6])), sort_keys=True))
    elif argv[:1] == ["submission-check"] and len(argv) == 5:
        print(json.dumps(submission_check(Path(argv[1]), *argv[2:5]), sort_keys=True))
    else:
        raise SystemExit("usage: ci_repair_provenance.py statement OUT_DIR | verify STATEMENT BUNDLE ATTESTATION_JSON PROPOSALS_DIR RESULT | submission-check STATEMENT BASE_SHA BASE_TREE CANDIDATE_TREE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
