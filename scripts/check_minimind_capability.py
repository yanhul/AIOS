#!/usr/bin/env python3
"""Check MiniMind as a capability provider, never as an executable workload."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--adapter", default="adapters/minimind/adapter.py")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    adapter = Path(args.adapter).resolve()
    env = os.environ.copy()
    env["MINIMIND_ROOT"] = str(root)
    proc = subprocess.run(
        [sys.executable, str(adapter)],
        text=True,
        capture_output=True,
        env=env,
        check=False,
        timeout=60,
    )
    if proc.returncode != 0:
        raise SystemExit(f"MiniMind capability adapter failed: {proc.stderr.strip()}")
    try:
        receipt = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise SystemExit("MiniMind capability adapter did not emit JSON") from exc

    if not isinstance(receipt, dict):
        raise SystemExit("MiniMind capability receipt must be a JSON object")
    required = {"status", "evidence_refs", "verification_refs", "provenance"}
    missing = required - receipt.keys()
    if missing:
        raise SystemExit(f"MiniMind capability receipt missing {sorted(missing)}")
    provenance = receipt["provenance"]
    if not isinstance(provenance, dict):
        raise SystemExit("MiniMind capability provenance must be an object")
    if provenance.get("producer") != "jingyaogong/minimind":
        raise SystemExit("MiniMind capability provenance producer mismatch")
    if provenance.get("adapter") != "minimind.model@1":
        raise SystemExit("MiniMind capability provenance adapter mismatch")
    for field in ("evidence_refs", "verification_refs"):
        refs = receipt[field]
        if not isinstance(refs, list) or not refs or not all(
            isinstance(ref, str) and ref.strip() for ref in refs
        ):
            raise SystemExit(
                f"MiniMind capability receipt {field} must be a non-empty list of strings"
            )
    if receipt["status"] not in {"AVAILABLE", "BLOCKED", "INCONCLUSIVE"}:
        raise SystemExit(f"Ungoverned MiniMind capability status: {receipt['status']}")

    # The check process can succeed while the capability is BLOCKED. Never label
    # that outcome CHECK_PASS: machine-readable status must carry the verdict.
    print(json.dumps({"MINIMIND_CAPABILITY_CHECK": receipt}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
