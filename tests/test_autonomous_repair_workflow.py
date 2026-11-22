from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_autonomous_repair_publishes_its_exact_candidate_branch():
    workflow = (ROOT / ".github/workflows/ci-autonomous-repair.yml").read_text(encoding="utf-8")
    block = workflow.split("      - name: Push verified candidate branch", 1)[1]
    assert 'branch="$(git branch --show-current)"' in block
    assert 'branch="$SOURCE_BRANCH"' not in block
    assert 'git push --set-upstream "$remote" "$branch"' in block
    assert 'PUBLISHED_CANDIDATE_SHA=$candidate_sha' in block


def test_each_repair_iteration_restarts_ci_and_remains_reviewable():
    workflow = (ROOT / ".github/workflows/ci-autonomous-repair.yml").read_text(encoding="utf-8")
    block = workflow.split("      - name: Push verified candidate branch", 1)[1]
    assert 'gh workflow run CI --repo' in block
    assert 'gh workflow run "G4A CI" --repo' in block
    assert 'gh pr list --repo' in block
    assert 'gh pr create --repo' in block
    assert '--draft' in block
