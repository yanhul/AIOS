#!/usr/bin/env python3
"""AIOS capability adapter for the external MiniMind model provider.

MiniMind is a reusable capability, not a workload. This adapter only reports
provider/artifact availability and provenance; it never fabricates model quality
or promotion evidence. A workload must supply its own evaluation contract and
locked holdout evidence before relying on MiniMind for a promoted result.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

CAPABILITY = "minimind.model@1"
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
        return emit("BLOCKED", ["minimind:external_checkout_missing"], ["provenance"],
                    "set MINIMIND_ROOT to a pinned MiniMind checkout")

    root = Path(root_value).resolve()
    if not root.is_dir():
        return emit("BLOCKED", ["minimind:checkout_not_found"], ["provenance"],
                    "MINIMIND_ROOT is not a directory")

    readme = root / "README.md"
    if not readme.is_file():
        return emit("BLOCKED", ["minimind:readme_missing"], ["provenance"],
                    "MiniMind checkout is incomplete")

    evidence = [f"minimind:readme_sha256={sha256_file(readme)}", "minimind:checkout_present"]
    for name in ("model", "dataset", "dataset.py", "model.py", "trainer", "eval_llm.py"):
        if (root / name).exists():
            evidence.append(f"minimind:path_present={name}")

    return emit("AVAILABLE", evidence, ["artifact_lineage", "provenance"],
                "provider availability verified; workload-specific quality evaluation remains external")


if __name__ == "__main__":
    raise SystemExit(main())
