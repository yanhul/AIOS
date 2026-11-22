import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ci_repair_provenance as prov  # noqa: E402
from core.repair_reconcile import patch_digest  # noqa: E402

REPO = "yanhul/AIOS"
WF_SHA = "a" * 40


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def _setup(tmp_path, monkeypatch, *, content="VALUE = 2\n", extra=None):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    for k, v in (("user.name", "t"), ("user.email", "t@t")):
        _git(repo, "config", k, v)
    (repo / "mod.py").write_text("VALUE = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")
    files = [{"path": "mod.py", "content": "VALUE = 2\n"}]
    pdir = tmp_path / "proposals"
    pdir.mkdir()
    (pdir / "repair-proposal-1.json").write_text(json.dumps(
        {"schema": 2, "attempt": 1, "run_id": 11, "repository": REPO, "base_sha": base, "files": files}))
    recon = {"status": "RECONCILED", "patch_digest": patch_digest(files), "test_digest": "t" * 64,
             "contract_id": "CT-x", "permit_id": "PT-x", "effects": [{"receipt_id": "PR-1"}]}
    result = tmp_path / "repair-result-1.json"
    result.write_text(json.dumps({"status": "REPAIR_E2E_PASS", "reconciliation": recon}))
    _git(repo, "switch", "-qc", "aios/autorepair/11-99")
    (repo / "mod.py").write_text(content)
    for path, body in (extra or {}).items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(body)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fix", "-m", "AIOS-Repair-Run: 99")
    for k, v in {"GITHUB_REPOSITORY": REPO, "AIOS_REPAIR_RUN_ID": "11", "AIOS_REPAIR_SOURCE_BRANCH": "aios/autorepair/x",
                 "AIOS_REPAIR_SHA": base, "GITHUB_RUN_ID": "99", "GITHUB_RUN_ATTEMPT": "1",
                 "GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/ci-autonomous-repair.yml@refs/heads/b",
                 "GITHUB_SHA": WF_SHA, "AIOS_REPAIR_PASS_ATTEMPT": "1", "AIOS_REPAIR_RESULT_FILE": str(result)}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.chdir(repo)
    out = tmp_path / "candidate"
    prov.statement(out)
    verifier = tmp_path / "verifier"
    _git(tmp_path, "clone", "-q", str(repo), str(verifier))
    _git(verifier, "checkout", "-q", "--detach", base)
    return out, pdir, result, verifier


def _attestation(tmp_path, run=99, sha=WF_SHA, workflow="ci-autonomous-repair.yml"):
    url = f"https://github.com/{REPO}"
    cert = {"sourceRepositoryURI": url, "sourceRepositoryDigest": sha, "runnerEnvironment": "github-hosted",
            "runInvocationURI": f"{url}/actions/runs/{run}/attempts/1",
            "buildSignerURI": f"{url}/.github/workflows/{workflow}@refs/heads/b"}
    path = tmp_path / f"att-{run}-{workflow}.json"
    path.write_text(json.dumps([{"verificationResult": {"signature": {"certificate": cert}}}]))
    return path


def _verify(tmp_path, out, pdir, result, verifier, att):
    return prov.verify(out / "candidate-provenance.json", out / "candidate.bundle", att, pdir, result, cwd=verifier)


def test_verified_candidate_passes(tmp_path, monkeypatch):
    out, pdir, result, verifier = _setup(tmp_path, monkeypatch)
    report = _verify(tmp_path, out, pdir, result, verifier, _attestation(tmp_path))
    assert report["status"] == "PROVENANCE_VERIFIED"


@pytest.mark.parametrize("kwargs", [{"run": 98}, {"sha": "b" * 40}, {"workflow": "other.yml"}])
def test_attestation_from_other_run_commit_or_workflow_is_rejected(tmp_path, monkeypatch, kwargs):
    out, pdir, result, verifier = _setup(tmp_path, monkeypatch)
    with pytest.raises(SystemExit, match="attestation is not from"):
        _verify(tmp_path, out, pdir, result, verifier, _attestation(tmp_path, **kwargs))


def test_candidate_content_must_equal_proposal(tmp_path, monkeypatch):
    out, pdir, result, verifier = _setup(tmp_path, monkeypatch, content="VALUE = 3\n")
    with pytest.raises(SystemExit, match="content != cumulative proposal"):
        _verify(tmp_path, out, pdir, result, verifier, _attestation(tmp_path))


def test_candidate_with_extra_protected_file_is_rejected(tmp_path, monkeypatch):
    out, pdir, result, verifier = _setup(tmp_path, monkeypatch, extra={".github/workflows/x.yml": "on: push\n"})
    with pytest.raises(SystemExit, match="protected paths"):
        _verify(tmp_path, out, pdir, result, verifier, _attestation(tmp_path))


def test_tampered_statement_is_rejected(tmp_path, monkeypatch):
    out, pdir, result, verifier = _setup(tmp_path, monkeypatch)
    path = out / "candidate-provenance.json"
    body = json.loads(path.read_text())
    body["repair_run_id"] = 100
    path.write_text(json.dumps(body))
    with pytest.raises(SystemExit, match="BLOCKED"):
        _verify(tmp_path, out, pdir, result, verifier, _attestation(tmp_path, run=100))


def test_reconciliation_record_swap_is_rejected(tmp_path, monkeypatch):
    out, pdir, result, verifier = _setup(tmp_path, monkeypatch)
    data = json.loads(result.read_text())
    data["reconciliation"]["test_digest"] = "f" * 64
    result.write_text(json.dumps(data))
    with pytest.raises(SystemExit, match="reconciliation record"):
        _verify(tmp_path, out, pdir, result, verifier, _attestation(tmp_path))


def test_candidate_branch_must_be_per_repair_run(tmp_path, monkeypatch):
    out, pdir, result, verifier = _setup(tmp_path, monkeypatch)
    path = out / "candidate-provenance.json"
    body = json.loads(path.read_text())
    body["candidate_branch"] = "aios/autorepair/e2e-chain"
    path.write_text(json.dumps(body))
    with pytest.raises(SystemExit, match="source-ci-run"):
        _verify(tmp_path, out, pdir, result, verifier, _attestation(tmp_path))


def test_candidate_branch_format():
    assert prov.candidate_branch(44990346556, "45011332245") == "aios/autorepair/44990346556-45011332245"
    with pytest.raises(SystemExit):
        prov.candidate_branch("1", "../main")


def test_submission_gate_accepts_fresh_non_noop_base():
    base = "a" * 40
    report = prov.validate_submission_base(
        {"base_sha": base}, base, "b" * 40, "c" * 40
    )
    assert report["status"] == "SUBMISSION_BASE_VERIFIED"


def test_submission_gate_blocks_moved_base():
    with pytest.raises(SystemExit, match="BASE_MOVED"):
        prov.validate_submission_base(
            {"base_sha": "a" * 40}, "b" * 40, "c" * 40, "d" * 40
        )


def test_submission_gate_blocks_noop_tree():
    with pytest.raises(SystemExit, match="NO_OP"):
        prov.validate_submission_base(
            {"base_sha": "a" * 40}, "a" * 40, "c" * 40, "c" * 40
        )


@pytest.mark.parametrize(
    "prov_data,base_sha,base_tree,candidate_tree,reason",
    [
        ({}, "a" * 40, "b" * 40, "c" * 40, "INVALID_ATTESTED_BASE_SHA"),
        ({"base_sha": "bad"}, "a" * 40, "b" * 40, "c" * 40, "INVALID_ATTESTED_BASE_SHA"),
        ({"base_sha": "z" * 40}, "a" * 40, "b" * 40, "c" * 40, "INVALID_ATTESTED_BASE_SHA"),
        ({"base_sha": "a" * 40}, "", "b" * 40, "c" * 40, "BASE_REF_UNRESOLVED"),
        ({"base_sha": "a" * 40}, "a" * 40, "", "c" * 40, "BASE_TREE_UNRESOLVED"),
        ({"base_sha": "a" * 40}, "a" * 40, "b" * 40, "", "CANDIDATE_TREE_UNRESOLVED"),
    ],
)
def test_submission_gate_fails_closed_on_missing_or_malformed_data(
    prov_data, base_sha, base_tree, candidate_tree, reason
):
    with pytest.raises(SystemExit, match=reason):
        prov.validate_submission_base(prov_data, base_sha, base_tree, candidate_tree)
