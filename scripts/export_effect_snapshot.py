#!/usr/bin/env python3
"""Export a validated UNKNOWN effect snapshot; does not sign or publish it."""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from core.effect_state_export import export_unknown_effect_snapshot
from core.mutation import canonical_json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--aios-dir", required=True)
    parser.add_argument("--effect-id", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists() or output.is_symlink():
        raise SystemExit("BLOCKED: output already exists")
    snapshot = export_unknown_effect_snapshot(args.aios_dir, args.effect_id, args.actor)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(canonical_json(snapshot) + "\n")
    print(json.dumps({"status": "UNKNOWN_EFFECT_SNAPSHOT_EXPORTED", "effect_id": args.effect_id,
                      "state": snapshot["state"], "attempt": snapshot["attempt"]}, sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(2)
