#!/usr/bin/env python3
"""AIOS test authoring gate.

Read-only by default. It checks only newly changed test files and requires
contract metadata for new/materially changed tests. It also reports common
low-value patterns without deleting or rewriting anything.
"""
from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from pathlib import Path

REQUIRED = {
    "AIOS-CONTRACT",
    "AIOS-REGRESSION",
    "AIOS-OWNER",
    "AIOS-COVERAGE-GAP",
    "AIOS-BASELINE",
}

PATTERNS = {
    "source_grep": ("open(", "read_text(", "Path(", "inspect.getsource"),
    "exact_string_assert": ("assert ", " in source", " in content", " == source"),
    "private_shape": ("._", "mock_calls", "call_args", "call_args_list"),
}

def git_files(base: str | None) -> list[str]:
    if base:
        cmd = ["git", "diff", "--name-only", f"{base}...HEAD", "--", "tests"]
    else:
        cmd = ["git", "diff", "--name-only", "HEAD^", "HEAD", "--", "tests"]
    out = subprocess.check_output(cmd, text=True).splitlines()
    return [p for p in out if p.endswith(".py")]

def markers(text: str) -> set[str]:
    return {line.split(":", 1)[0].strip() for line in text.splitlines()
            if line.lstrip().startswith("# AIOS-") and ":" in line}

def assertion_count(tree: ast.AST) -> int:
    return sum(isinstance(n, ast.Assert) for n in ast.walk(tree))

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", help="base ref for PR diff, e.g. origin/main")
    ap.add_argument("paths", nargs="*", help="explicit test paths; overrides git diff")
    args = ap.parse_args()

    paths = args.paths or git_files(args.base)
    if not paths:
        print("TEST_AUDIT: no changed Python tests")
        return 0

    failures: list[str] = []
    warnings: list[str] = []

    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            failures.append(f"{raw}: file not found")
            continue
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            failures.append(f"{raw}: syntax error: {exc}")
            continue

        missing = REQUIRED - markers(text)
        if missing:
            failures.append(f"{raw}: missing authoring-gate metadata: {sorted(missing)}")

        if assertion_count(tree) == 0:
            warnings.append(f"{raw}: assertion-free test module")

        lowered = text.lower()
        if any(token.lower() in lowered for token in PATTERNS["source_grep"]):
            warnings.append(f"{raw}: source-inspection token present; verify it protects an independent contract")
        if any(token.lower() in lowered for token in PATTERNS["private_shape"]):
            warnings.append(f"{raw}: implementation-coupling token present; verify owner-boundary necessity")

    for warning in warnings:
        print("TEST_AUDIT WARNING:", warning)
    for failure in failures:
        print("TEST_AUDIT FAIL:", failure)

    if failures:
        print(f"TEST_AUDIT: BLOCKED ({len(failures)} authoring-gate failure(s))")
        return 1
    print(f"TEST_AUDIT: PASS ({len(paths)} changed test file(s)); warnings={len(warnings)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
