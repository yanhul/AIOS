from __future__ import annotations

import json
import subprocess
from pathlib import Path

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


def test_trusted_tests_run_in_separate_worktree_and_cannot_dirty_candidate(tmp_path, monkeypatch):
    base = init_repo(tmp_path)
    proposal = {
        "schema": 2,
        "run_id": 17,
        "repository": "yanhul/AIOS",
        "base_sha": base,
        "attempt": 1,
        "files": [{"path": "module.py", "content": "VALUE = 2\n"}],
    }
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")
    apply_result = {
        "schema": 1,
        "status": "PATCH_APPLIED_RECEIPTS_ACCEPTED",
        "run_id": 17,
        "repository": "yanhul/AIOS",
        "base_sha": base,
    }
    (tmp_path / "repair-apply-result.json").write_text(
        json.dumps(apply_result), encoding="utf-8"
    )
    monkeypatch.setenv("AIOS_REPAIR_RUN_ID", "17")
    monkeypatch.setenv("AIOS_REPAIR_SHA", base)
    monkeypatch.setenv("GITHUB_REPOSITORY", "yanhul/AIOS")
    monkeypatch.setenv("AIOS_REPAIR_PROPOSALS", str(proposal_path))
    monkeypatch.chdir(tmp_path)

    assert trusted_tests.main() == 0

    result = json.loads((tmp_path / "repair-test-result.json").read_text(encoding="utf-8"))
    assert result["status"] == "PASS"
    assert result["results"][0]["returncode"] == 0
    assert (tmp_path / "module.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert not (tmp_path / "research-artifact.json").exists()
