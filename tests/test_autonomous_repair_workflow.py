from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_repair_trigger_is_enabled_for_same_repo_main_prs_only():
    workflow = (ROOT / ".github/workflows/ci-autonomous-repair.yml").read_text(encoding="utf-8")
    assert "workflow_run:" in workflow
    assert "      - CI" in workflow
    assert "      - G4A CI" in workflow
    assert "github.event.workflow_run.head_repository.full_name == github.repository" in workflow
    assert "github.event.workflow_run.pull_requests[0].base.ref == 'main'" in workflow
    assert "github.event.workflow_run.pull_requests[0].head.repo.full_name == github.repository" in workflow


def test_autonomous_repair_publishes_its_exact_candidate_branch():
    workflow = (ROOT / ".github/workflows/ci-autonomous-repair.yml").read_text(encoding="utf-8")
    publisher = (ROOT / "scripts/ci_repair_publish.py").read_text(encoding="utf-8")
    block = workflow.split("      - name: Push verified candidate branch", 1)[1]
    assert 'branch="$(git branch --show-current)"' in block
    assert 'branch="$SOURCE_BRANCH"' not in block
    assert 'git push --set-upstream "$remote" "$branch"' in block
    assert 'PUBLISHED_CANDIDATE_SHA=$candidate_sha' in block
    assert 'branch = f"aios/autorepair/{run_id}"' in publisher
    assert 'branch = source_branch' not in publisher


def test_each_repair_iteration_restarts_ci_and_remains_reviewable():
    workflow = (ROOT / ".github/workflows/ci-autonomous-repair.yml").read_text(encoding="utf-8")
    block = workflow.split("      - name: Push verified candidate branch", 1)[1]
    assert 'gh workflow run CI --repo' in block
    assert 'gh workflow run "G4A CI" --repo' in block
    assert 'gh pr list --repo' in block
    assert 'gh pr create --repo' in block
    assert '--draft' in block
    assert "Human review and merge required." in block
