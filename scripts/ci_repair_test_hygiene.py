"""Keep deterministic test-generated research outputs out of repair patches.

These four tracked JSON files are rewritten by the repository test suite. They
are test side effects, not proposal-owned source changes. Restore only these
explicitly enumerated paths after tests; every other mutation remains visible
to the strict proposal/publish scope checks.
"""
from __future__ import annotations

from collections.abc import Callable

TEST_GENERATED_TRACKED_PATHS = frozenset({
    "research/artifacts/absorption-promotion.json",
    "research/artifacts/absorption-repair.json",
    "research/artifacts/absorption-runtime-proof.json",
    "research/artifacts/absorption.json",
})


def restore_test_generated_artifacts(git: Callable[..., str]) -> tuple[str, ...]:
    staged = set(git("diff", "--cached", "--name-only").splitlines())
    forbidden_staged = sorted(staged & TEST_GENERATED_TRACKED_PATHS)
    if forbidden_staged:
        raise SystemExit(
            "BLOCKED: test-generated artifact paths were staged: "
            + ", ".join(forbidden_staged)
        )

    changed = set(git("diff", "--name-only").splitlines())
    restore = tuple(sorted(changed & TEST_GENERATED_TRACKED_PATHS))
    if not restore:
        return ()

    for path in restore:
        git("ls-files", "--error-unmatch", "--", path)
    git("restore", "--worktree", "--", *restore)

    remaining = set(git("diff", "--name-only").splitlines()) & TEST_GENERATED_TRACKED_PATHS
    if remaining:
        raise SystemExit(
            "BLOCKED: unable to restore test-generated artifact paths: "
            + ", ".join(sorted(remaining))
        )
    return restore
