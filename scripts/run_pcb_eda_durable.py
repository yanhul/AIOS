#!/usr/bin/env python3
"""Run pcb.eda@1 as a governed durable PCB audit/repair workload.

BLOCKED is not an automatic retry. AIOS first discovers and verifies the
specific evidence required by the observed blocker, persists those verified
references, and only then permits a new pcb.eda@1 attempt.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from typing import Any, Mapping

from adapters.pcb_eda.adapter import run_kit
from core.pcb_eda import PcbEdaRequest, validate_kit_receipt
from core.durable_loop import LoopPolicy, run_durable_loop
from core.blocked_continuation import classify_blockers, plan_blocked_continuation


class JsonStateStore:
    def __init__(self, path: Path): self.path = path
    def load(self): return json.loads(self.path.read_text()) if self.path.exists() else None
    def save(self, state): self.path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")


def _load_json(path: Path) -> Mapping[str, Any]:
    if not path.is_file():
        return {}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return obj if isinstance(obj, Mapping) else {}
    except Exception:
        return {}


def _verified_requirement(requirement: str, summary: Mapping[str, Any], plan: Mapping[str, Any]) -> bool:
    industrial = plan.get("industrial_rule_authority") if isinstance(plan.get("industrial_rule_authority"), Mapping) else {}
    rules = industrial.get("rules") if isinstance(industrial.get("rules"), Mapping) else {}
    placement = plan.get("placement") if isinstance(plan.get("placement"), Mapping) else {}
    routing = plan.get("routing") if isinstance(plan.get("routing"), Mapping) else {}
    checks = placement.get("checks") if isinstance(placement.get("checks"), Mapping) else {}
    lock = placement.get("lock") if isinstance(placement.get("lock"), Mapping) else {}

    if requirement == "placement_geometry":
        return placement.get("status") == "VERIFIED" and checks.get("all_positions_authoritative") is True
    if requirement == "board_outline":
        return checks.get("board_bounds_available") is True
    if requirement == "clearance_rule":
        v = rules.get("board_edge_clearance")
        return isinstance(v, Mapping) and v.get("status") in {"APPLICABLE", "NOT_APPLICABLE"} and (v.get("status") != "NOT_APPLICABLE" or bool(v.get("evidence")))
    if requirement == "mechanical_envelope":
        return isinstance(checks.get("component_envelope_count"), int) and checks["component_envelope_count"] > 0
    if requirement == "assembly_constraint":
        v = rules.get("assembly_access")
        return isinstance(v, Mapping) and v.get("status") in {"APPLICABLE", "NOT_APPLICABLE"} and (v.get("status") != "NOT_APPLICABLE" or bool(v.get("evidence")))
    if requirement == "placement_authority":
        return lock.get("status") == "LOCKED"
    if requirement in {"load_requirement", "copper_capacity_rule", "electrical_authority"}:
        v = rules.get("current_capacity")
        return isinstance(v, Mapping) and v.get("status") in {"APPLICABLE", "NOT_APPLICABLE"} and (v.get("status") != "NOT_APPLICABLE" or bool(v.get("evidence")))
    if requirement == "net_connectivity_evidence":
        return summary.get("gates", {}).get("G3_CONNECTIVITY") == "VERIFIED"
    if requirement == "routing_authority":
        return industrial.get("status") == "VERIFIED"
    if requirement == "closure_verification":
        return routing.get("status") == "VERIFIED"
    return False


def discover_evidence(state: Mapping[str, Any], output_root: Path) -> dict[str, Any]:
    """Verify only evidence already emitted by the Kit; never synthesize PCB facts."""
    latest = state.get("latest_attempt_dir")
    attempt_dir = Path(latest) if isinstance(latest, str) else output_root / f"attempt-{state.get('step', 0)}"
    summary = _load_json(attempt_dir / "summary.json")
    plan = _load_json(attempt_dir / "placement-routing-plan.json")
    blockers = state.get("blocked_requirements") or []
    verified = set(state.get("verified_evidence_refs") or [])
    unresolved = []
    refs = {}
    for req in blockers:
        if _verified_requirement(req, summary, plan):
            ref = str((attempt_dir / ("summary.json" if req in {"net_connectivity_evidence"} else "placement-routing-plan.json")).resolve())
            verified.add(ref)
            refs[req] = ref
        else:
            unresolved.append(req)
    return {
        "status": "PASS" if not unresolved else "BLOCKED",
        "verified_evidence_refs": sorted(verified),
        "unresolved_requirements": unresolved,
        "evidence_refs": refs,
        "source_attempt": str(attempt_dir.resolve()),
    }


class PcbExecutor:
    def __init__(self, args): self.args = args

    def observe(self, state):
        return {"capability": "pcb.eda@1", "step": state.get("step", 0),
                "continuation": state.get("continuation")}

    def decide(self, observation, state):
        op = (state.get("continuation") or {}).get("next_operation_id", "pcb.eda@1")
        return {"logical_operation_id": op, "authority": "AIOS_CONTROL_PLANE"}

    def act(self, decision, state):
        op = decision["logical_operation_id"]
        if op == "pcb.eda.discover_evidence":
            result = discover_evidence(state, self.args.output)
            state_verified = set(state.get("verified_evidence_refs") or [])
            state_verified.update(result["verified_evidence_refs"])
            state["verified_evidence_refs"] = sorted(state_verified)
            state["blocked_requirements"] = result["unresolved_requirements"]
            state["discovery"] = result
            if result["status"] == "PASS":
                state["continuation"] = {
                    "authority": "AIOS_CONTROL_PLANE",
                    "evidence_refs": sorted(state_verified),
                    "next_operation_id": "pcb.eda@1",
                    "reason": "discovery verified required blocker evidence",
                }
            return {"operation": op, **result}
        if op != "pcb.eda@1":
            raise RuntimeError(f"unauthorized PCB operation: {op}")

        attempt_no = state.get("step", 0) + 1
        attempt_dir = self.args.output / f"attempt-{attempt_no}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        task = f"{self.args.task_id}-attempt-{attempt_no}"
        req = PcbEdaRequest(
            task_id=task, input_dir=str(self.args.input), output_dir=str(attempt_dir),
            kit_root=str(self.args.kit_root),
            config=str(self.args.config) if self.args.config else None,
            repair=True, max_retries=self.args.kit_retries,
        )
        rc, receipt = run_kit(req)
        state["latest_attempt_dir"] = str(attempt_dir.resolve())
        return {"operation": op, "returncode": rc, "receipt": receipt, "attempt_dir": str(attempt_dir.resolve())}

    def verify(self, result, state):
        if result.get("operation") == "pcb.eda.discover_evidence":
            return {
                "status": "READY" if result["status"] == "PASS" else "BLOCKED",
                "state_patch": {
                    "verified_evidence_refs": result["verified_evidence_refs"],
                    "blocked_requirements": result["unresolved_requirements"],
                    "discovery": result,
                    **({"continuation": {
                        "authority": "AIOS_CONTROL_PLANE",
                        "evidence_refs": result["verified_evidence_refs"],
                        "next_operation_id": "pcb.eda@1",
                        "reason": "discovery verified required blocker evidence",
                    }} if result["status"] == "PASS" else {}),
                },
                "blockers": [{"id": f"EVIDENCE:{x}", "status": "BLOCKED"} for x in result["unresolved_requirements"]],
                "receipt": {
                    "effect_id": f"{self.args.task_id}:effect:{state.get('step', 0)+1}",
                    "attempt_id": f"{self.args.task_id}:attempt:{state.get('step', 0)+1}",
                    "status": "OBSERVED",
                    "evidence": {"provider": "aios-control-plane-evidence-discovery", "discovery_result": result},
                },
            }
        receipt = result["receipt"]
        blockers = receipt.get("blockers") or receipt.get("findings") or []
        kinds = classify_blockers({"blockers": blockers})
        state["blocked_requirements"] = []
        if kinds:
            plan = plan_blocked_continuation({"blockers": blockers}, state)
            state["blocked_requirements"] = list(plan.get("requires_verification", [])) if plan else []
        attempt_dir = result.get("attempt_dir")
        if not isinstance(attempt_dir, str) or not attempt_dir.strip():
            raise RuntimeError("PCB EDA action result missing attempt_dir")
        return {
            "status": receipt["status"],
            "state_patch": {
                "latest_attempt_dir": attempt_dir,
                "blocked_requirements": list(plan.get("requires_verification", [])) if False else state.get("blocked_requirements", []),
            },
            "blockers": blockers,
            "classified_blockers": kinds,
            "receipt": {
                "effect_id": f"{self.args.task_id}:effect:{state.get('step', 0)+1}",
                "attempt_id": f"{self.args.task_id}:attempt:{state.get('step', 0)+1}",
                "status": "OBSERVED",
                "evidence": {
                    "provider": "altium-audit-kit",
                    "summary": str(Path(attempt_dir) / "summary.json"),
                    "summary_sha256": hashlib.sha256((Path(attempt_dir) / "summary.json").read_bytes()).hexdigest(),
                    "receipt_schema": receipt.get("schema"),
                    "terminal_reason": receipt.get("terminal_reason"),
                    "gates": receipt.get("gates"),
                },
            },
            "kit_receipt": receipt,
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-id", required=True); ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True); ap.add_argument("--kit-root", type=Path, required=True)
    ap.add_argument("--config", type=Path); ap.add_argument("--state", type=Path, required=True)
    ap.add_argument("--max-steps", type=int, default=6); ap.add_argument("--kit-retries", type=int, default=3)
    a = ap.parse_args(); a.output.mkdir(parents=True, exist_ok=True)

    def continuation(v, s):
        if v.get("status") == "BLOCKED":
            raw = v.get("blockers") or []
            if raw and all(isinstance(x, dict) and str(x.get("id", "")).startswith("EVIDENCE:") for x in raw):
                return None
        blockers = v.get("classified_blockers") or classify_blockers(v)
        if not blockers:
            return None
        return plan_blocked_continuation({"blockers": [x["source"] for x in blockers]}, s)

    def terminal(v, s):
        status = v.get("status")
        if status == "PASS": return "PASS"
        if status == "BLOCKED": return "BLOCKED"
        return None

    def validate_execution_receipt(receipt: Mapping[str, Any], state: Mapping[str, Any]) -> None:
        evidence = receipt.get("evidence")
        intent = state.get("in_flight_attempt")
        if not isinstance(evidence, Mapping) or not isinstance(intent, Mapping):
            raise ValueError("PCB receipt evidence or persisted intent is missing")
        if receipt.get("effect_id") != intent.get("effect_id") or receipt.get("attempt_id") != intent.get("attempt_id"):
            raise ValueError("PCB receipt does not match persisted execution intent")
        decision = intent.get("decision")
        operation = decision.get("logical_operation_id") if isinstance(decision, Mapping) else None
        if operation == "pcb.eda.discover_evidence":
            if evidence.get("provider") != "aios-control-plane-evidence-discovery":
                raise ValueError("evidence-discovery receipt provider identity is invalid")
            discovery = evidence.get("discovery_result")
            if not isinstance(discovery, Mapping) or discovery.get("status") not in {"PASS", "BLOCKED"}:
                raise ValueError("evidence-discovery receipt is incomplete")
            refs = discovery.get("verified_evidence_refs")
            if discovery.get("status") == "PASS" and (
                not isinstance(refs, list) or not refs
                or not all(isinstance(ref, str) and ref.strip() for ref in refs)
            ):
                raise ValueError("evidence-discovery PASS lacks verified evidence refs")
            return
        if evidence.get("provider") != "altium-audit-kit":
            raise ValueError("PCB receipt provider identity is invalid")
        summary = Path(str(evidence.get("summary", ""))).resolve(strict=True)
        output_root = a.output.resolve(strict=True)
        if not summary.is_relative_to(output_root) or summary.name != "summary.json":
            raise ValueError("PCB receipt artifact escapes the governed output directory")
        if hashlib.sha256(summary.read_bytes()).hexdigest() != evidence.get("summary_sha256"):
            raise ValueError("PCB receipt artifact digest mismatch")
        actual = json.loads(summary.read_text(encoding="utf-8"))
        validate_kit_receipt(actual)
        if actual.get("schema") != evidence.get("receipt_schema"):
            raise ValueError("PCB receipt schema does not match the persisted artifact")
        if actual.get("terminal_reason") != evidence.get("terminal_reason"):
            raise ValueError("PCB receipt terminal reason does not match the persisted artifact")
        if actual.get("gates") != evidence.get("gates"):
            raise ValueError("PCB receipt gates do not match the persisted artifact")

    def validate_state_patch(patch: Mapping[str, Any], receipt: Mapping[str, Any], state: Mapping[str, Any]) -> None:
        evidence = receipt.get("evidence")
        intent = state.get("in_flight_attempt")
        if not isinstance(evidence, Mapping) or not isinstance(intent, Mapping):
            raise ValueError("PCB state patch lacks receipt evidence or execution intent")
        decision = intent.get("decision")
        operation = decision.get("logical_operation_id") if isinstance(decision, Mapping) else None
        if operation == "pcb.eda.discover_evidence":
            discovery = evidence.get("discovery_result")
            if not isinstance(discovery, Mapping):
                raise ValueError("discovery state patch has no source result")
            refs = discovery.get("verified_evidence_refs")
            unresolved = discovery.get("unresolved_requirements")
            if not isinstance(refs, list) or not isinstance(unresolved, list):
                raise ValueError("discovery state patch source lists are invalid")
            expected = {
                "verified_evidence_refs": refs,
                "blocked_requirements": unresolved,
                "discovery": dict(discovery),
            }
            if discovery.get("status") == "PASS":
                expected["continuation"] = {
                    "authority": "AIOS_CONTROL_PLANE",
                    "evidence_refs": refs,
                    "next_operation_id": "pcb.eda@1",
                    "reason": "discovery verified required blocker evidence",
                }
            if dict(patch) != expected:
                raise ValueError("discovery state patch differs from validated discovery receipt")
            return
        summary = Path(str(evidence.get("summary", ""))).resolve(strict=True)
        raw = summary.read_bytes()
        if hashlib.sha256(raw).hexdigest() != evidence.get("summary_sha256"):
            raise ValueError("PCB state patch receipt digest mismatch")
        actual = json.loads(raw.decode("utf-8"))
        validate_kit_receipt(actual)
        blockers = actual.get("blockers") or actual.get("findings") or []
        kinds = classify_blockers({"blockers": blockers})
        plan = plan_blocked_continuation({"blockers": blockers}, state) if kinds else None
        expected = {
            "latest_attempt_dir": str(summary.parent.resolve()),
            "blocked_requirements": list(plan.get("requires_verification", [])) if plan else [],
        }
        if dict(patch) != expected:
            raise ValueError("PCB state patch does not match validated Audit Kit receipt")

    policy = LoopPolicy(
        max_steps=a.max_steps, terminal_evaluator=terminal,
        action_authorizer=lambda d, s: None, require_execution_receipt=True,
        execution_receipt_validator=validate_execution_receipt,
        state_patch_validator=validate_state_patch,
        blocked_continuation=continuation,
    )
    result = run_durable_loop(PcbExecutor(a), JsonStateStore(a.state), policy)
    print(json.dumps(result, indent=2, default=str))
    raise SystemExit(0 if result["status"] == "PASS" else 2)


if __name__ == "__main__":
    main()
