"""Apply the existing fail-closed evidence gate to absorption verification.

Promotion here means promotion of a governed AIOS-native adaptation proposal into
the review/absorption queue. It never mutates AIOS source code automatically.
"""
from __future__ import annotations
import json
import os
from pathlib import Path

from core.evidence_gate import gate_promotion

INPUT = Path(os.environ.get("AIOS_ABSORPTION_VERIFY_OUT", "research/artifacts/absorption-verification.json"))
OUT = Path(os.environ.get("AIOS_ABSORPTION_PROMOTION_OUT", "research/artifacts/absorption-promotion.json"))

def promote(data: dict) -> dict:
    decisions = []
    blocked = []
    for record in data.get("records", []):
        decision = gate_promotion(record, required_level="VERIFIED_DIGITAL")
        item = {
            "candidate_id": record.get("candidate_id"),
            "run_id": record.get("run_id"),
            "source_ref": record.get("source_ref"),
            "claim": record.get("claim"),
            "level": record.get("level"),
            "allowed": decision.allowed,
            "reason": decision.reason,
            "action": "PROMOTE_TO_AI0S_REVIEW_QUEUE" if decision.allowed else "HOLD",
        }
        (decisions if decision.allowed else blocked).append(item)
    result = {
        "schema_version": 1,
        "kind": "AIOS_ABSORPTION_PROMOTION",
        "run_id": data.get("run_id"),
        "decisions": decisions,
        "blocked": blocked,
        "overall": "PASS" if decisions and not blocked and data.get("overall") == "PASS" else "BLOCKED",
        "source_mutation": False,
        "external_code_execution": False,
        "authority": "AIOS_CONTROL_PLANE",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    result = promote(json.loads(INPUT.read_text(encoding="utf-8")))
    raise SystemExit(0 if result["overall"] == "PASS" else 1)
