"""Fail-closed promotion requiring authenticated evidence and same-run artifact integrity."""
from __future__ import annotations
import hashlib, json, os, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from core.evidence_gate import gate_promotion
from core.artifact_attestation import attest_artifact, verify_artifact_attestation

DEFAULT_INPUT = Path("research/artifacts/absorption-verification.json")
DEFAULT_RUNTIME = Path("research/artifacts/absorption-runtime-proof.json")
DEFAULT_OUT = Path("research/artifacts/absorption-promotion.json")


def _path(env_name, default):
    return Path(os.environ.get(env_name, str(default)))


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _verification_valid(data):
    expected = _digest({"verified": data.get("records", []), "failures": data.get("failures", [])})
    return isinstance(data.get("digest"), str) and data["digest"] == expected


def _runtime_valid(runtime):
    if not isinstance(runtime.get("implementation"), dict) or not isinstance(runtime.get("probes"), dict):
        return False
    expected = _digest({"implementation": runtime["implementation"], "probes": runtime["probes"]})
    return runtime.get("digest") == expected


def promote(data: dict, runtime: dict | None = None, *, run_id: str | None = None) -> dict:
    runtime = runtime or {}
    expected_run = run_id or os.environ.get("GITHUB_RUN_ID", "")
    lineage_errors = []
    if not expected_run:
        lineage_errors.append("current run_id is required")
    if data.get("run_id") != expected_run:
        lineage_errors.append("verification artifact run_id mismatch")
    if runtime.get("run_id") != expected_run:
        lineage_errors.append("runtime proof run_id mismatch")
    if data.get("overall") != "PASS":
        lineage_errors.append("independent verification is not PASS")
    secret = os.environ.get("AIOS_EVIDENCE_SIGNING_SECRET")
    if not secret or len(secret) < 16:
        lineage_errors.append("trusted artifact signing secret is not configured")
    if not verify_artifact_attestation("AIOS_ABSORPTION_RUNTIME_PROOF", expected_run,
                                       runtime.get("digest", ""), runtime.get("attestation"), secret or ""):
        lineage_errors.append("runtime proof HMAC attestation is missing or invalid")
    if not _verification_valid(data):
        lineage_errors.append("verification artifact content digest mismatch")
    if not _runtime_valid(runtime):
        lineage_errors.append("runtime proof content digest mismatch")
    runtime_ok = runtime.get("overall") == "PASS" and not lineage_errors
    decisions, blocked = [], []
    for record in data.get("records", []):
        if record.get("run_id") != expected_run:
            decision = None
            reason = "verified record run_id mismatch"
        elif lineage_errors:
            decision = None
            reason = "; ".join(lineage_errors)
        else:
            decision = gate_promotion(record, required_level="VERIFIED_DIGITAL")
            reason = decision.reason if not decision.allowed else ""
        allowed = bool(decision and decision.allowed and runtime_ok)
        item = {"candidate_id": record.get("candidate_id"), "run_id": record.get("run_id"),
                "source_ref": record.get("source_ref"), "claim": record.get("claim"),
                "level": record.get("level"), "allowed": allowed,
                "action": "PROMOTE_TO_ABSORBED_REGISTRY" if allowed else "HOLD",
                "verdict": "PROMOTE" if allowed else "DEFER"}
        if not allowed:
            item["reason"] = reason or "implementation/runtime proof is not PASS"
            blocked.append(item)
        else:
            decisions.append(item)
    for failure in data.get("failures", []):
        blocked.append({"candidate_id": failure.get("candidate_id"), "run_id": data.get("run_id"),
                        "source_ref": failure.get("source_ref"), "allowed": False, "action": "HOLD",
                        "verdict": "DEFER", "level": failure.get("level", "UNKNOWN"),
                        "reason": "; ".join(failure.get("errors", [])) or "independent verification did not complete",
                        "errors": failure.get("errors", [])})
    if lineage_errors and not blocked:
        blocked.append({"candidate_id": None, "run_id": data.get("run_id"), "allowed": False,
                        "action": "HOLD", "verdict": "DEFER", "level": "UNKNOWN",
                        "reason": "; ".join(lineage_errors)})
    result = {"schema_version": 4, "kind": "AIOS_ABSORPTION_PROMOTION",
              "run_id": expected_run, "input_verification_run_id": data.get("run_id"),
              "input_verification_digest": data.get("digest"),
              "input_runtime_run_id": runtime.get("run_id"),
              "input_runtime_digest": runtime.get("digest"),
              "decisions": decisions, "blocked": blocked,
              "candidate_count": len(decisions) + len(blocked), "promoted_count": len(decisions),
              "deferred_count": len(blocked),
              "overall": "PASS" if decisions and not blocked and runtime_ok
                         else "PASS_WITH_HOLDS" if decisions or blocked else "BLOCKED",
              "implementation_runtime_proof": runtime_ok, "source_mutation": False,
              "external_code_execution": False, "authority": "AIOS_CONTROL_PLANE"}
    result["digest"] = _digest(result)
    if secret and len(secret) >= 16:
        result["attestation"] = attest_artifact("AIOS_ABSORPTION_PROMOTION", expected_run,
                                                result["digest"], secret)
    else:
        result["overall"] = "BLOCKED"
    out = _path("AIOS_ABSORPTION_PROMOTION_OUT", DEFAULT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    verification = json.loads(_path("AIOS_ABSORPTION_VERIFY_OUT", DEFAULT_INPUT).read_text())
    runtime_path = _path("AIOS_ABSORPTION_RUNTIME_IN", DEFAULT_RUNTIME)
    runtime = json.loads(runtime_path.read_text()) if runtime_path.exists() else {}
    result = promote(verification, runtime, run_id=os.environ.get("GITHUB_RUN_ID", ""))
    raise SystemExit(0 if result["overall"] in {"PASS", "PASS_WITH_HOLDS"} else 1)
