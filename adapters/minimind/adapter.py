#!/usr/bin/env python3
"""Verify the pinned upstream MiniMind source layout and executable model surface.

This is a provider smoke test, not a model-quality or training-readiness claim.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

CAPABILITY = "minimind.model@1"
OWNER = "jingyaogong/minimind"
REQUIRED_FILES = (
    "README.md",
    "model/__init__.py",
    "model/model_minimind.py",
    "model/tokenizer.json",
    "model/tokenizer_config.json",
    "dataset/__init__.py",
    "dataset/lm_dataset.py",
    "trainer/train_agent.py",
    "trainer/rollout_engine.py",
    "eval_llm.py",
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def git_head(root: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True, stderr=subprocess.DEVNULL, timeout=5,
        ).strip() or None
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
        return emit("BLOCKED", ["minimind:external_checkout_missing"], ["provenance"],
                    "set MINIMIND_ROOT to a pinned MiniMind checkout")

    root = Path(root_value).resolve()
    if not root.is_dir():
        return emit("BLOCKED", ["minimind:checkout_not_found"], ["provenance"],
                    "MINIMIND_ROOT is not a directory")

    missing = [name for name in REQUIRED_FILES if not (root / name).is_file()]
    if missing:
        return emit("BLOCKED", [f"minimind:path_missing={name}" for name in missing],
                    ["artifact_lineage", "provenance"], "required MiniMind source files are missing")

    head = git_head(root)
    expected = os.environ.get("MINIMIND_EXPECTED_REV")
    if expected and head != expected:
        return emit("BLOCKED", [f"minimind:git_head={head or 'unknown'}",
                                f"minimind:expected_rev={expected}"],
                    ["artifact_lineage", "provenance"],
                    "MiniMind checkout does not match the required immutable revision")

    # Import and instantiate the real upstream classes; a directory-only check is insufficient.
    try:
        sys.path.insert(0, str(root))
        import torch
        model_module = importlib.import_module("model.model_minimind")
        dataset_module = importlib.import_module("dataset.lm_dataset")
        config_cls = getattr(model_module, "MiniMindConfig")
        model_cls = getattr(model_module, "MiniMindForCausalLM")
        dataset_cls = getattr(dataset_module, "AgentRLDataset")
        config = config_cls(
            hidden_size=32, num_hidden_layers=1, vocab_size=64,
            num_attention_heads=4, num_key_value_heads=2,
            head_dim=8, max_position_embeddings=32, flash_attn=False,
        )
        model = model_cls(config).eval()
        with torch.inference_mode():
            output = model(torch.tensor([[1, 2, 3]], dtype=torch.long))
        if tuple(output.logits.shape) != (1, 3, 64):
            raise RuntimeError(f"unexpected logits shape: {tuple(output.logits.shape)}")
        if not callable(getattr(dataset_cls, "__getitem__", None)):
            raise RuntimeError("AgentRLDataset is not a Dataset implementation")
    except Exception as exc:
        return emit("BLOCKED", [f"minimind:provider_smoke_failed={type(exc).__name__}:{exc}"],
                    ["artifact_lineage", "python_import", "model_forward", "dataset_api"],
                    "pinned MiniMind provider failed executable smoke verification")

    evidence = [
        f"minimind:readme_sha256={sha256_file(root / 'README.md')}",
        *[f"minimind:file_present={name}" for name in REQUIRED_FILES],
        f"minimind:git_head={head or 'unknown'}",
        "minimind:import=MiniMindConfig,MiniMindForCausalLM,AgentRLDataset",
        "minimind:model_forward=PASS:input_shape=1x3:logits_shape=1x3x64",
    ]
    return emit("AVAILABLE", evidence,
                ["artifact_lineage", "provenance", "python_import", "model_forward", "dataset_api"],
                "source/API smoke verified; weights, datasets, training, evaluation quality and promotion remain separately unverified")


if __name__ == "__main__":
    raise SystemExit(main())
