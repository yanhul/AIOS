"""Runtime + implementation proof for AIOS-native absorbed primitives.

This proof executes only AIOS-owned code. It binds implementation conformance,
runtime behavior, and fail-closed lineage into one durable evidence artifact.
"""
from __future__ import annotations
import hashlib, json, os
from pathlib import Path

from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop
from core.durable_runtime import RuntimeSubmission, validate_submission
from core.evidence import EvidenceRecord, verify_evidence
from research.absorbed_capabilities import run_conformance

OUT = Path(os.environ.get("AIOS_ABSORPTION_RUNTIME_PROOF_OUT", "research/artifacts/absorption-runtime-proof.json"))

def _digest(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def _durable_loop_probe():
    class E:
        def observe(self, state): return {"seen": state["step"]}
        def decide(self, observation, state): return {"op": "probe"}
        def act(self, decision, state): return {"ok": True}
        def verify(self, action_result, state):
            return {"status": "PASS", "receipt": {"effect_id":"probe-effect","attempt_id":f"attempt-{state['step']+1}","status":"OBSERVED","evidence":{"probe":"ok"}}}
    policy = LoopPolicy(max_steps=1, terminal_evaluator=lambda verification, state: verification["status"],
                        action_authorizer=lambda decision, state: None, require_execution_receipt=True)
    result = run_durable_loop(E(), MemoryStateStore(), policy)
    return result.get("status") == "PASS" and result.get("terminal_evidence", {}).get("verification", {}).get("receipt", {}).get("status") == "OBSERVED"

def _evidence_probe():
    r = EvidenceRecord("absorption-runtime-proof", "VERIFIED_DIGITAL", "aios://absorption-runtime",
                        "AIOS_NATIVE_ABSORBED_PRIMITIVE_RUNTIME_PROOF",
                        os.environ.get("GITHUB_RUN_ID","local"), "AIOS_RUNTIME").as_record()
    return verify_evidence(r)

def _runtime_probe():
    effect = {"effect_id":"effect-proof"}
    validate_submission(effect, RuntimeSubmission("effect-proof","attempt-proof","AIOS_RUNTIME"), "attempt-proof", "AIOS_RUNTIME")
    try:
        validate_submission(effect, RuntimeSubmission("wrong","attempt-proof","AIOS_RUNTIME"), "attempt-proof", "AIOS_RUNTIME")
    except ValueError:
        return True
    return False

def run():
    implementation = run_conformance()
    probes = {
        "implementation_conformance": implementation["overall"] == "PASS",
        "durable_execution": _durable_loop_probe(),
        "evidence_provenance": _evidence_probe(),
        "retry_provider_lineage": _runtime_probe(),
    }
    result = {
        "schema_version": 2,
        "kind": "AIOS_ABSORPTION_RUNTIME_PROOF",
        "run_id": os.environ.get("GITHUB_RUN_ID","local"),
        "implementation": implementation,
        "probes": probes,
        "passed_count": sum(probes.values()),
        "total_count": len(probes),
        "overall": "PASS" if all(probes.values()) else "BLOCKED",
        "external_code_execution": False,
        "external_code_copy": False,
        "source_mutation": False,
        "digest": _digest({"implementation": implementation, "probes": probes}),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["overall"] == "PASS" else 1)
