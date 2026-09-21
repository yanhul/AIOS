"""Bounded autonomous re-verification loop for absorption failures.

This runner does not mutate source. Each obligation gets a bounded retry budget,
re-runs only AIOS-owned absorption tests, and emits explicit lineage. A retry
that passes is REVERIFIED, not REPAIRED; source repair requires a separate,
authorized mutation stage.
"""
from __future__ import annotations
import hashlib, json, os, subprocess, sys
from pathlib import Path

OUT = Path(os.environ.get("AIOS_ABSORPTION_REPAIR_OUT", "research/artifacts/absorption-repair.json"))
MAX_ATTEMPTS = int(os.environ.get("AIOS_ABSORPTION_REPAIR_MAX_ATTEMPTS", "2"))
if MAX_ATTEMPTS < 1:
    raise ValueError("AIOS_ABSORPTION_REPAIR_MAX_ATTEMPTS must be >= 1")
TESTS = [
    "tests/test_absorption_executor.py",
    "tests/test_absorption_pipeline.py",
    "tests/test_absorption_verifier.py",
    "tests/test_absorption_repair.py",
]

def _digest(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True).encode()).hexdigest()

def _tests():
    p = subprocess.run(
        [sys.executable, "-m", "pytest", *TESTS, "-q"],
        capture_output=True, text=True, timeout=180,
    )
    return p.returncode == 0, _digest((p.stdout or "") + (p.stderr or ""))

def run(verification: dict, *, run_id: str):
    failures = verification.get("failures", [])
    obligations = [
        {
            "obligation_id": "repair-" + _digest(f)[:16],
            "candidate_id": f.get("candidate_id"),
            "errors": f.get("errors", []),
            "attempts": 0,
            "status": "OPEN",
        }
        for f in failures
    ]
    repaired = []
    for obligation in obligations:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            obligation["attempts"] = attempt
            passed, digest = _tests()
            obligation["test_digest"] = digest
            if passed:
                obligation["status"] = "REPROVED"
                repaired.append(obligation)
                break
        if obligation["status"] == "OPEN":
            obligation["status"] = "BLOCKED_BUDGET_EXHAUSTED"
    result = {
        "schema_version": 1,
        "kind": "AIOS_ABSORPTION_REPAIR_PROOF",
        "run_id": run_id,
        "max_attempts": MAX_ATTEMPTS,
        "obligation_count": len(obligations),
        "reverified_count": len(repaired),
        "blocked_count": sum(x["status"].startswith("BLOCKED") for x in obligations),
        "obligations": obligations,
        "overall": "PASS" if not obligations or all(x["status"] == "REVERIFIED" for x in obligations) else "BLOCKED",
        "authority": "AIOS_CONTROL_PLANE",
        "source_mutation": False,
        "external_code_execution": False,
        "digest": _digest(obligations),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    inp = Path(os.environ.get("AIOS_ABSORPTION_VERIFY_IN", "research/artifacts/absorption-verification.json"))
    result = run(json.loads(inp.read_text(encoding="utf-8")), run_id=os.environ.get("GITHUB_RUN_ID", "local"))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["overall"] == "PASS" else 1)
