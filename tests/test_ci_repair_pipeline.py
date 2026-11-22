import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from cli.aios import _project_path
from core.authority import authorize, load_contract, load_permit
from core.ci_supervisor import CIEventError, DurableCIInbox
from core.effect_authority import _effect_rel
from core.verification import _verification_relpath
from scripts.ci_repair_common import (
    issue_repair_authority,
    load_proposals,
    proposals_digest,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci-autonomous-repair.yml"
BASE = "a" * 40


def _workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_repair_workflow_only_triggers_on_dispatch():
    wf = _workflow()
    assert set(wf[True]) == {"workflow_dispatch"}  # PyYAML parses the `on` key as True
    text = WORKFLOW.read_text(encoding="utf-8")
    for dead in ("workflow_run", "pull_request_target", "github.event_name"):
        assert dead not in text


def test_repair_workflow_run_scripts_do_not_interpolate_untrusted_expressions():
    for job in _workflow()["jobs"].values():
        for step in job["steps"]:
            script = step.get("run", "")
            for expr in ("${{ inputs.", "${{ github.ref_name", "${{ github.event", "${{ env."):
                assert expr not in script


def test_repair_test_jobs_are_isolated_from_secrets_and_write_tokens():
    jobs = _workflow()["jobs"]
    for n in (1, 2, 3):
        test_job = jobs[f"test{n}"]
        assert test_job["permissions"] == {"contents": "read"}
        assert "secrets." not in json.dumps(test_job)
        assert "github.token" not in json.dumps(test_job)
        apply_job = jobs[f"apply{n}"]
        assert "pytest" not in json.dumps(apply_job)
        assert "AIOS_AUTHORITY_ATTESTATION_SECRET" in json.dumps(apply_job)
    for name, job in jobs.items():
        if not (name.startswith("apply") or name == "publish"):
            assert "AIOS_AUTHORITY_ATTESTATION_SECRET" not in json.dumps(job)
    publish = jobs["publish"]
    assert "needs.test1.result == 'success'" in publish["if"]
    assert "repair-result" not in json.dumps(publish)


def _proposal(tmp_path, attempt, files):
    path = tmp_path / f"repair-proposal-{attempt}.json"
    path.write_text(json.dumps({"schema": 2, "attempt": attempt, "base_sha": BASE,
                                "files": [{"path": p, "content": c} for p, c in files]}))
    return path


@pytest.mark.parametrize("path", ["conftest.py", "pkg/conftest.py", "pyproject.toml", "pytest.ini",
                                  "sitecustomize.py", "pkg/evil.pth", ".github/actions/x.yml"])
def test_repair_proposals_cannot_touch_test_harness(tmp_path, path):
    with pytest.raises(SystemExit):
        load_proposals([_proposal(tmp_path, 1, [(path, "x")])], BASE)


def test_repair_proposals_must_be_contiguous_and_current(tmp_path):
    p1 = _proposal(tmp_path, 1, [("a.py", "1")])
    p3 = _proposal(tmp_path, 3, [("a.py", "3")])
    with pytest.raises(SystemExit):
        load_proposals([p1, p3], BASE)
    with pytest.raises(SystemExit):
        load_proposals([p1], "b" * 40)
    assert [p["attempt"] for p in load_proposals([p1], BASE)] == [1]


def test_repair_authority_requires_deployment_secret(tmp_path, monkeypatch):
    monkeypatch.delenv("AIOS_AUTHORITY_ATTESTATION_SECRET")
    with pytest.raises(SystemExit, match="AIOS_AUTHORITY_ATTESTATION_SECRET"):
        issue_repair_authority(tmp_path, actor="a", task_id="t", input_digest="sha256:x")


def test_repair_authority_binds_proposals_digest(tmp_path):
    proposals = load_proposals([_proposal(tmp_path, 1, [("a.py", "1")])], BASE)
    aios = tmp_path / "aios"
    aios.mkdir()
    digest = proposals_digest(proposals)
    contract_id, permit_id = issue_repair_authority(aios, actor="a", task_id="t", input_digest=digest)
    assert authorize(str(aios), contract_id, permit_id)
    assert load_contract(str(aios), contract_id)["input_digest"] == digest


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def _repo(path):
    path.mkdir()
    _git(path, "init", "-q")
    (path / "mod.py").write_text("VALUE = 1\n")
    _git(path, "add", ".")
    _git(path, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base")
    return _git(path, "rev-parse", "HEAD")


def _run(script, cwd, env):
    return subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=cwd,
                          env={**os.environ, "PYTHONPATH": str(ROOT), **env},
                          capture_output=True, text=True)


def test_isolated_test_tree_matches_trusted_apply_record(tmp_path):
    base = _repo(tmp_path / "apply")
    _git(tmp_path, "clone", "-q", str(tmp_path / "apply"), str(tmp_path / "test"))
    proposals = []
    for n, files in ((1, [("mod.py", "VALUE = 2\n")]), (2, [("pkg/new.py", "X = 1\n")])):
        path = tmp_path / f"repair-proposal-{n}.json"
        path.write_text(json.dumps({"schema": 2, "attempt": n, "base_sha": base,
                                    "files": [{"path": p, "content": c} for p, c in files]}))
        proposals.append(str(path))
    record = tmp_path / "repair-apply-2.json"
    env = {"AIOS_REPAIR_SHA": base, "AIOS_REPAIR_RUN_ID": "7", "AIOS_REPAIR_ATTEMPT": "2",
           "AIOS_REPAIR_PROPOSALS": ",".join(proposals), "AIOS_REPAIR_APPLY_RECORD": str(record)}
    applied = _run("ci_repair_apply_attempt.py", tmp_path / "apply", env)
    assert applied.returncode == 0, applied.stderr
    data = json.loads(record.read_text())
    assert set(data["files"]) == {"mod.py", "pkg/new.py"}

    staged = _run("ci_repair_stage_test_tree.py", tmp_path / "test", env)
    assert staged.returncode == 0, staged.stderr
    assert (tmp_path / "test/pkg/new.py").read_text() == "X = 1\n"

    _git(tmp_path, "clone", "-q", str(tmp_path / "apply"), str(tmp_path / "publish"))
    _git(tmp_path / "publish", "checkout", "-q", "--", ".")
    apply_dir = tmp_path / "apply-records"
    apply_dir.mkdir()
    (apply_dir / "repair-apply-2.json").write_text(record.read_text())
    published = _run("ci_repair_publish.py", tmp_path / "publish", {
        **env, "AIOS_REPAIR_PASS_ATTEMPT": "2", "AIOS_REPAIR_PROPOSALS_DIR": str(tmp_path),
        "AIOS_REPAIR_APPLY_DIR": str(apply_dir), "AIOS_REPAIR_SOURCE_BRANCH": "main"})
    assert published.returncode == 0, published.stderr
    assert _git(tmp_path / "publish", "rev-parse", "--abbrev-ref", "HEAD") == "aios/autorepair/7"

    data["proposals_digest"] = "sha256:" + "0" * 64
    record.write_text(json.dumps(data))
    _git(tmp_path / "test", "checkout", "-q", "--", ".")
    _git(tmp_path / "test", "clean", "-qfd")
    tampered = _run("ci_repair_stage_test_tree.py", tmp_path / "test", env)
    assert tampered.returncode != 0
    assert "not bound" in tampered.stdout + tampered.stderr


def test_cli_reports_invalid_project_id(capsys):
    from cli.aios import main
    assert main(["inspect", "../etc"]) == 2
    assert "invalid project id" in capsys.readouterr().err


@pytest.mark.parametrize("bad", ["../x", "CT-../../etc", "", "CT-" + "g" * 64])
def test_authority_rejects_malformed_ids(tmp_path, bad):
    with pytest.raises(ValueError):
        load_contract(str(tmp_path), bad)
    with pytest.raises(ValueError):
        load_permit(str(tmp_path), bad.replace("CT-", "PT-"))


@pytest.mark.parametrize("bad", ["../x", "EF-../../x", "VF-" + "0" * 63])
def test_path_bound_ids_reject_traversal(tmp_path, bad):
    with pytest.raises(ValueError):
        _effect_rel(bad)
    with pytest.raises(ValueError):
        _verification_relpath(bad)
    with pytest.raises(CIEventError):
        DurableCIInbox(str(tmp_path))._path(bad)


@pytest.mark.parametrize("bad", ["../x", "a/b", "", ".hidden"])
def test_cli_rejects_project_path_traversal(bad):
    with pytest.raises(ValueError):
        _project_path(bad)
