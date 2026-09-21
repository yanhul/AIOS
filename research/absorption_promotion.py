"""Apply the existing fail-closed evidence gate to absorption verification.

Promotion here means promotion of a governed AIOS-native adaptation proposal into
the review/absorption queue. It never mutates AIOS source code automatically.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from core.evidence_gate import gate_promotion

def _path(env_name, default):
    return Path(os.environ.get(env_name, str(default)))

DEFAULT_INPUT = Path("research/artifacts/absorption-verification.json")
DEFAULT_OUT = Path("research/artifacts/absorption-promotion.json")

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
            "action": "PROMOTE_TO_AIOS_REVIEW_QUEUE" if decision.allowed else "HOLD",
        }
        if decision.allowed:
            item["verdict"] = "PROMOTE"
            decisions.append(item)
        else:
            item["verdict"] = "DEFER"
            blocked.append(item)
    # Preserve every verifier failure as an explicit candidate-level verdict.
    for failure in data.get("failures", []):
        blocked.append({
            "candidate_id": failure.get("candidate_id"),
            "run_id": data.get("run_id"),
            "source_ref": failure.get("source_ref"),
            "allowed": False,
            "action": "HOLD",
            "verdict": "DEFER",
            "level": failure.get("level", "UNKNOWN"),
            "reason": "; ".join(failure.get("errors", [])) or "independent verification did not complete",
            "errors": failure.get("errors", []),
        })
    result = {
        "schema_version": 1,
        "kind": "AIOS_ABSORPTION_PROMOTION",
        "run_id": data.get("run_id"),
        "decisions": decisions,
        "blocked": blocked,
        "candidate_count": len(decisions) + len(blocked),
        "promoted_count": len(decisions),
        "deferred_count": len(blocked),
        "overall": (
            "PASS" if decisions and not blocked and data.get("overall") == "PASS"
            else "PASS_WITH_HOLDS" if decisions or blocked
            else "BLOCKED"
        ),
        "source_mutation": False,
        "external_code_execution": False,
        "authority": "AIOS_CONTROL_PLANE",
    }
    out = _path("AIOS_ABSORPTION_PROMOTION_OUT", DEFAULT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    result = promote(json.loads(_path("AIOS_ABSORPTION_VERIFY_OUT", DEFAULT_INPUT).read_text(encoding="utf-8")))
    raise SystemExit(0 if result["overall"] in {"PASS", "PASS_WITH_HOLDS"} else 1)
