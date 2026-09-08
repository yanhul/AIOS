#!/usr/bin/env python3
"""AIOS adapter for the external MiniMind learning workload.

This adapter never fabricates a training/evaluation result.  When a pinned
MiniMind checkout is supplied through MINIMIND_ROOT it performs a lightweight,
deterministic artifact/evaluation preflight.  Without the external checkout it
terminates BLOCKED with explicit evidence, which is a governed terminal state.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

CAPABILITY = "minimind.learning@1"
OWNER = "jingyaogong/minimind"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


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
            "set MINIMIND_ROOT to a pinned MiniMind checkout for learning evaluation",
        )

    root = Path(root_value).resolve()
    if not root.is_dir():
        return emit("BLOCKED", ["minimind:checkout_not_found"], ["provenance"], "MINIMIND_ROOT is not a directory")

    readme = root / "README.md"
    if not readme.is_file():
        return emit("BLOCKED", ["minimind:readme_missing"], ["provenance"], "MiniMind checkout is incomplete")

    tracked_candidates = [root / "model", root / "dataset", root / "dataset.py", root / "model.py", root / "trainer"]
    existing = [p for p in tracked_candidates if p.exists()]
    evidence = [f"minimind:readme_sha256={sha256_file(readme)}"]
    evidence.append("minimind:checkout_present")
    if existing:
        evidence.append("minimind:core_paths_present=" + str(len(existing)))

    # This is deliberately a preflight, not a fabricated quality claim.
    # Promotion requires an independently produced evaluation + locked holdout.
    return emit(
        "INCONCLUSIVE",
        evidence,
        ["artifact_lineage", "provenance"],
        "checkout preflight passed; independent evaluation and locked holdout are still required",
    )


if __name__ == "__main__":
    raise SystemExit(main())
