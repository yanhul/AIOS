#!/usr/bin/env python3
"""AIOS capability adapter for the external MiniMind model provider.

MiniMind is a reusable capability, not a workload. This adapter verifies that
an explicitly supplied checkout contains the model/runtime surfaces needed by
the capability and emits provenance. It does not claim that upstream Agentic
RL or OPD/GKD PRs are merged, and it never fabricates model-quality evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

CAPABILITY = "minimind.model@1"
OWNER = "jingyaogong/minimind"
REQUIRED_PATHS = (
    "model",
    "dataset",
    "dataset.py",
    "model.py",
    "trainer",
    "trainer/train_agent.py",
    "trainer/rollout_engine.py",
    "eval_llm.py",
)
OPTIONAL_DIRECTION_PATHS = (
    "trainer/train_agentic_rl_async.py",
    "trainer/train_opd.py",
    "trainer/opd_utils.py",
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def git_head(root: Path) -> str | None:
    try:
        value = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).strip()
        return value or None
    except (OSError, subprocess.SubprocessError):
        return None


def emit(status: str, evidence: list[str], verification: list[str], reason: str | None = None) -> int:
    result = {
        "status": status,
        "evidence_refs": evidence,
        "verification_refs": verification,
        "provenance": {"producer": OWNER, "adapter": CAPABILITY},
    }
    if reason:
        result["reason"] = reason
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def main() -> int:
    root_value = os.environ.get("MINIMIND_ROOT")
    if not root_value:
        return emit(
            "BLOCKED",
            ["minimind:external_checkout_missing"],
            ["provenance"],
            "set MINIMIND_ROOT to a pinned MiniMind checkout",
        )

    root = Path(root_value).resolve()
    if not root.is_dir():
        return emit("BLOCKED", ["minimind:checkout_not_found"], ["provenance"], "MINIMIND_ROOT is not a directory")

    readme = root / "README.md"
    if not readme.is_file():
        return emit("BLOCKED", ["minimind:readme_missing"], ["provenance"], "MiniMind checkout is incomplete")

    missing = [name for name in REQUIRED_PATHS if not (root / name).exists()]
    if missing:
        return emit(
            "BLOCKED",
            [f"minimind:path_missing={name}" for name in missing],
            ["artifact_lineage", "provenance"],
            "required MiniMind capability/runtime surface is incomplete",
        )

    head = git_head(root)
    expected = os.environ.get("MINIMIND_EXPECTED_REV")
    if expected and head != expected:
        return emit(
            "BLOCKED",
            [f"minimind:git_head={head or 'unknown'}", f"minimind:expected_rev={expected}"],
            ["artifact_lineage", "provenance"],
            "MiniMind checkout does not match the required immutable revision",
        )

    evidence = [
        f"minimind:readme_sha256={sha256_file(readme)}",
        "minimind:checkout_present",
        *[f"minimind:path_present={name}" for name in REQUIRED_PATHS],
    ]
    if head:
        evidence.append(f"minimind:git_head={head}")

    for name in OPTIONAL_DIRECTION_PATHS:
        evidence.append(
            f"minimind:direction_surface={name}:{'present' if (root / name).exists() else 'absent'}"
        )

    return emit(
        "AVAILABLE",
        evidence,
        ["artifact_lineage", "provenance"],
        "provider availability verified; Agentic RL/async/OPD quality and promotion remain workload-specific and externally evaluated",
    )


if __name__ == "__main__":
    raise SystemExit(main())
