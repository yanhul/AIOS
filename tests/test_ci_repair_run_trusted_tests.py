from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import ci_repair_run_trusted_tests as trusted_tests


def init_repo(root: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "AIOS Test"], cwd=root, check=True)
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_side_effect.py").write_text(
        "from pathlib import Path\n"
        "def test_candidate_patch_and_side_effect():\n"
        "    assert Path('module.py').read_text() == 'VALUE = 2\\n'\n"
        "    Path('research-artifact.json').write_text('{\\\"touched\\\": true}')\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "module.py", "tests"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True,
        capture_output=True, check=True,
    ).stdout.strip()


def test_trusted_test_environment_is_allowlisted_and_uses_private_home(tmp_path):
    source = {
        "PATH": "/usr/bin:/bin",
        "GITHUB_TOKEN": "must-not-leak",
        "ACTIONS_RUNTIME_TOKEN": "must-not-leak",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "must-not-leak",
        "TRY_PROVIDER_TOKEN": "must-not-leak",
        "AIOS_PROVIDER_KEYRING": "must-not-leak",
        "JAVA_HOME": "/opt/java",
    }
    env = trusted_tests._trusted_test_env(
        test_root=tmp_path / "repo", home=tmp_path / "home", tmp=tmp_path / "tmp",
        run_id=17, repository="yanhul/AIOS", source_env=source,
    )
    assert "must-not-leak" not in env.values()
    assert not ({"GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                 "TRY_PROVIDER_TOKEN", "AIOS_PROVIDER_KEYRING"} & env.keys())
    assert env["HOME"] == str(tmp_path / "home")
    assert env["PYTHONPATH"] == str(tmp_path / "repo")
    assert env["JAVA_HOME"] == "/opt/java"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not all(shutil.which(x) for x in ("sudo", "unshare", "setpriv")),
    reason="OS namespace sandbox requires Linux sudo, unshare and setpriv",
)
def test_trusted_tests_run_in_network_and_pid_sandbox_without_git_metadata(tmp_path, monkeypatch):
    base = init_repo(tmp_path)
    proposal = {
        "schema": 2, "run_id": 17, "repository": "yanhul/AIOS",
        "base_sha": base, "attempt": 1,
        "files": [{"path": "module.py", "content": "VALUE = 2\n"}],
    }
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")
    (tmp_path / "repair-apply-result.json").write_text(json.dumps({
        "schema": 1, "status": "PATCH_APPLIED_RECEIPTS_ACCEPTED",
        "run_id": 17, "repository": "yanhul/AIOS", "base_sha": base,
    }), encoding="utf-8")
    monkeypatch.setenv("AIOS_REPAIR_RUN_ID", "17")
    monkeypatch.setenv("AIOS_REPAIR_SHA", base)
    monkeypatch.setenv("GITHUB_REPOSITORY", "yanhul/AIOS")
    monkeypatch.setenv("AIOS_REPAIR_PROPOSALS", str(proposal_path))
    monkeypatch.setenv("AIOS_REPAIR_REQUIRE_OS_SANDBOX", "1")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-reach-child")
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "must-not-reach-child")
    monkeypatch.chdir(tmp_path)

    assert trusted_tests.main() == 0
    result = json.loads((tmp_path / "repair-test-result.json").read_text(encoding="utf-8"))
    assert result["status"] == "PASS"
    assert result["results"][0]["returncode"] == 0
    assert result["isolation"]["source_checkout_git_metadata"] == "NOT_EXPOSED"
    assert result["isolation"]["environment"] == "ALLOWLIST_ONLY"
    assert result["isolation"]["os_sandbox"] == "REQUIRED_AND_USED"
    assert result["isolation"]["network"] == "DENIED"
    assert result["isolation"]["pid_namespace"] == "ISOLATED"
    assert result["isolation"]["uid"] == 65534
    assert (tmp_path / "module.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert not (tmp_path / "research-artifact.json").exists()
