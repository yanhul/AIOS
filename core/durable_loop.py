"""Governed durable execution loop."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from .fix_protocol import FixPlan, require_fix_plan, require_fix_proof, FixProof
from .acceptance import AcceptancePredicate, evaluate_acceptance
from .continue_contract import validate_continue_contract

TERMINAL = frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"})

# Verifier state patches are data-plane observations only. These fields are
# owned by the durable control-plane state machine and can never be patched by
# an executor/verifier.
_PROTECTED_STATE_FIELDS = frozenset({
    "step",
    "status",
    "history",
    "terminal_evidence",
    "continue_contract",
    "policy_digest",
    "in_flight_attempt",
})

class StateStore(Protocol):
    def load(self) -> Mapping[str, Any] | None: ...
    def save(self, state: Mapping[str, Any]) -> None: ...

class Executor(Protocol):
    def observe(self, state: Mapping[str, Any]) -> Any: ...
    def decide(self, observation: Any, state: Mapping[str, Any]) -> Any: ...
    def act(self, decision: Any, state: Mapping[str, Any]) -> Any: ...
    def verify(self, action_result: Any, state: Mapping[str, Any]) -> Any: ...

@dataclass(frozen=True)
class LoopPolicy:
    max_steps: int
    terminal_evaluator: Callable[[Any, Mapping[str, Any]], str | None]
    action_authorizer: Callable[[Any, Mapping[str, Any]], None]
    resume_validator: Callable[[Mapping[str, Any]], None] | None = None
    policy_digest: str | None = None
    terminal_states: frozenset[str] = TERMINAL
    budget_exhaustion_state: str = "INCONCLUSIVE"
    failure_state: str = "BLOCKED"
    require_execution_receipt: bool = False
    execution_receipt_validator: Callable[[Mapping[str, Any], Mapping[str, Any]], None] | None = None
    fix_plan: FixPlan | None = None
    fix_success_state: str = "PASS"
    blocked_continuation: Callable[[Any, Mapping[str, Any]], Mapping[str, Any] | None] | None = None
    acceptance_predicates: tuple[AcceptancePredicate, ...] = ()
    continue_contract_builder: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        if self.policy_digest is not None and (not isinstance(self.policy_digest, str) or not self.policy_digest.strip()):
            raise ValueError("policy_digest must be a non-empty string when supplied")
        if not self.terminal_states or not all(isinstance(v, str) and v.strip() for v in self.terminal_states):
            raise ValueError("terminal_states must be a non-empty set of strings")
        if not isinstance(self.budget_exhaustion_state, str) or not self.budget_exhaustion_state.strip():
            raise ValueError("budget_exhaustion_state must be a non-empty string")
        if self.budget_exhaustion_state not in self.terminal_states:
            raise ValueError("budget_exhaustion_state must be an authorized terminal state")
        if not isinstance(self.failure_state, str) or not self.failure_state.strip():
            raise ValueError("failure_state must be a non-empty string")
        if self.failure_state not in self.terminal_states:
            raise ValueError("failure_state must be an authorized terminal state")
        if not isinstance(self.require_execution_receipt, bool):
            raise ValueError("require_execution_receipt must be boolean")
        if self.execution_receipt_validator is not None and not callable(self.execution_receipt_validator):
            raise ValueError("execution_receipt_validator must be callable")
        if self.fix_plan is not None:
            if not isinstance(self.fix_success_state, str) or not self.fix_success_state.strip():
                raise ValueError("fix_success_state must be a non-empty string")
            if self.fix_success_state not in self.terminal_states:
                raise ValueError("fix_success_state must be an authorized terminal state")
        if self.fix_plan is not None:
            require_fix_plan(self.fix_plan)
        if not isinstance(self.acceptance_predicates, tuple) or any(not isinstance(p, AcceptancePredicate) for p in self.acceptance_predicates):
            raise ValueError("acceptance_predicates must be a tuple of AcceptancePredicate")
        if self.blocked_continuation is not None and not callable(self.blocked_continuation):
            raise ValueError("blocked_continuation must be callable")
        if self.continue_contract_builder is not None and not callable(self.continue_contract_builder):
            raise ValueError("continue_contract_builder must be callable")

def _validate_execution_receipt(verification: Any) -> Mapping[str, Any]:
    """Fail closed unless verification contains a complete execution receipt."""
    if not isinstance(verification, Mapping):
        raise ValueError("execution receipt missing from verification")
    receipt = verification.get("receipt")
    if not isinstance(receipt, Mapping):
        raise ValueError("execution receipt missing from verification")
    required = ("effect_id", "attempt_id", "status")
    if any(not isinstance(receipt.get(key), str) or not receipt[key].strip() for key in required):
        raise ValueError("execution receipt lineage is incomplete")
    status = receipt.get("status")
    if status not in {"OBSERVED", "UNKNOWN"}:
        raise ValueError("execution receipt has unauthorized status")
    evidence = receipt.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise ValueError("execution receipt evidence is missing or empty")
    return receipt


def _validate_terminal_evidence(state: Mapping[str, Any]) -> None:
    """A terminal state is valid only when its immutable evidence projection exists."""
    evidence = state.get("terminal_evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("terminal state has no terminal evidence")
    if evidence.get("status") != state.get("status"):
        raise ValueError("terminal evidence status does not match state")
    if not isinstance(evidence.get("step"), int) or evidence["step"] != state.get("step"):
        raise ValueError("terminal evidence step does not match state")
    if "verification" not in evidence:
        raise ValueError("terminal evidence verification is missing")

@dataclass
class MemoryStateStore:
    state: dict[str, Any] = field(default_factory=dict)
    def load(self) -> Mapping[str, Any] | None:
        return deepcopy(self.state) if self.state else None
    def save(self, state: Mapping[str, Any]) -> None:
        self.state = deepcopy(dict(state))

def _validate_loaded_state(state: Mapping[str, Any], policy: LoopPolicy) -> None:
    if not isinstance(state.get("step"), int) or isinstance(state.get("step"), bool):
        raise ValueError("persisted step is invalid")
    if state["step"] < 0 or state["step"] > policy.max_steps:
        raise ValueError("persisted step exceeds immutable execution budget")
    if state.get("status") not in {"RUNNING", *policy.terminal_states}:
        raise ValueError("persisted status is invalid")
    if not isinstance(state.get("history"), list):
        raise ValueError("persisted history is invalid")
    if state.get("status") in policy.terminal_states:
        _validate_terminal_evidence(state)
    if policy.policy_digest is not None and state.get("policy_digest") != policy.policy_digest:
        raise ValueError("persisted policy digest does not match current policy")
    if policy.resume_validator is not None:
        policy.resume_validator(state)
    if policy.continue_contract_builder is not None:
        contract = state.get("continue_contract")
        # A fresh RUNNING state may bootstrap its first continuation projection.
        # Once durable progress exists, absence/mismatch is a resume-integrity failure.
        bootstrap = (
            contract is None
            and state.get("status") == "RUNNING"
            and state.get("step") == 0
            and not state.get("history")
        )
        if bootstrap:
            return
        if not isinstance(contract, Mapping):
            raise ValueError("persisted continue contract is missing")
        validate_continue_contract(contract)
        source_state = dict(state)
        source_state.pop("continue_contract", None)
        expected = policy.continue_contract_builder(source_state)
        if dict(contract) != dict(expected):
            raise ValueError("persisted continue contract does not match durable state")
    if state.get("status") in policy.terminal_states:
        _validate_terminal_evidence(state)

def _persist_state(state: dict[str, Any], store: StateStore, policy: LoopPolicy) -> None:
    """Persist a complete durable snapshot with its continuation projection."""
    candidate = deepcopy(state)
    if candidate.get("status") in policy.terminal_states and not isinstance(candidate.get("terminal_evidence"), Mapping):
        candidate["terminal_evidence"] = {
            "step": candidate.get("step", 0),
            "status": candidate["status"],
            "verification": {"reason": candidate.get("block_reason", "TERMINAL_STATE")},
        }
    if policy.continue_contract_builder is not None:
        contract = policy.continue_contract_builder(deepcopy(candidate))
        if not isinstance(contract, Mapping):
            raise ValueError("continue contract builder must return a mapping")
        candidate["continue_contract"] = deepcopy(dict(contract))
    store.save(candidate)
    state.clear()
    state.update(deepcopy(candidate))


def _apply_state_patch(state: dict[str, Any], patch: Mapping[str, Any]) -> None:
    """Validate and copy the entire verifier patch before mutating durable state."""
    if not isinstance(patch, Mapping):
        raise ValueError("verification state_patch must be a mapping")
    # Validate all keys before touching state; otherwise a malformed later key
    # could leave earlier fields partially applied when the caller fails closed.
    for key in patch:
        if not isinstance(key, str) or not key.strip():
            raise ValueError("verification state_patch keys must be non-empty strings")
    protected = sorted(_PROTECTED_STATE_FIELDS.intersection(patch))
    if protected:
        raise ValueError(f"verification state_patch attempts protected fields: {protected}")
    # Deep-copy all values up front as deepcopy itself can fail for an object.
    # Updating only after preparation makes the mutation all-or-nothing.
    prepared = {key: deepcopy(value) for key, value in patch.items()}
    state.update(prepared)


def _persist_raw_state(state: Mapping[str, Any], store: StateStore) -> None:
    """Persist an invalid durable snapshot without rebuilding governed projections."""
    store.save(deepcopy(dict(state)))

def _persist_or_fail_closed(state: dict[str, Any], store: StateStore, policy: LoopPolicy) -> bool:
    """Commit a durable snapshot or fail without claiming the state was persisted."""
    try:
        _persist_state(state, store, policy)
    except Exception as exc:
        fallback = deepcopy(state)
        fallback["status"] = policy.failure_state
        fallback["block_reason"] = f"durable persistence failed: {type(exc).__name__}: {exc}"
        try:
            _persist_raw_state(fallback, store)
        except Exception as raw_exc:
            raise RuntimeError(
                "durable persistence is UNKNOWN; governed snapshot could not be committed: "
                f"{type(raw_exc).__name__}: {raw_exc}"
            ) from raw_exc
        state.clear()
        state.update(fallback)
        return False
    return True

def _validate_fix_success(verification: Any, expected_state: str) -> None:
    """Require externally verifiable runtime proof before fix promotion."""
    if expected_state == "PASS":
        if not isinstance(verification, Mapping) or verification.get("status") != "FIXED":
            raise ValueError("PASS in a governed fix workflow requires status=FIXED")
        proof = verification.get("fix_proof")
        if not isinstance(proof, FixProof):
            raise ValueError("FIXED requires verifier-supplied FixProof")
        require_fix_proof(proof)

def run_durable_loop(executor: Executor, store: StateStore, policy: LoopPolicy) -> Mapping[str, Any]:
    """Run/resume OBSERVE -> DECIDE -> ACT -> VERIFY -> PERSIST with governed receipt/fix enforcement."""
    loaded = store.load()
    state: dict[str, Any] = deepcopy(dict(loaded or {}))
    state.setdefault("step", 0)
    state.setdefault("status", "RUNNING")
    state.setdefault("history", [])
    if policy.policy_digest is not None:
        state.setdefault("policy_digest", policy.policy_digest)
    try:
        _validate_loaded_state(state, policy)
    except Exception as exc:
        state["status"] = policy.failure_state
        state["block_reason"] = f"invalid durable state: {type(exc).__name__}: {exc}"
        _persist_raw_state(state, store)
        return state
    if state["status"] in policy.terminal_states:
        return state
    # A persisted in-flight intent means a prior process may have crossed the
    # external side-effect boundary without committing its receipt. Never replay it.
    if policy.require_execution_receipt and state.get("in_flight_attempt") is not None:
        state["status"] = policy.failure_state
        state["block_reason"] = "unresolved in-flight execution attempt; explicit provider reconciliation required"
        _persist_or_fail_closed(state, store, policy)
        return state
    # Preflight and durably commit the continuation projection before any side effect.
    # Missing contract inputs must block before ACT, not after an effect has already occurred.
    if policy.continue_contract_builder is not None and "continue_contract" not in state:
        if not _persist_or_fail_closed(state, store, policy):
            return state
    while state["step"] < policy.max_steps:
        try:
            observation = executor.observe(deepcopy(state))
            decision = executor.decide(deepcopy(observation), deepcopy(state))
        except Exception as exc:
            state["status"] = policy.failure_state
            state["block_reason"] = f"execution failed before authorization: {type(exc).__name__}: {exc}"
            if not _persist_or_fail_closed(state, store, policy):

                return state
            return state
        try:
            policy.action_authorizer(deepcopy(decision), deepcopy(state))
        except Exception as exc:
            state["status"] = policy.failure_state
            state["block_reason"] = f"action authorization failed: {type(exc).__name__}: {exc}"
            if not _persist_or_fail_closed(state, store, policy):

                return state
            return state
        try:
            if policy.require_execution_receipt:
                # Write-ahead intent: persist stable effect/attempt identity before
                # invoking provider code. A crash after this point blocks replay.
                intent = {
                    "effect_id": "effect-" + uuid4().hex,
                    "attempt_id": "attempt-" + uuid4().hex,
                    "decision": deepcopy(decision),
                    "observation": deepcopy(observation),
                    "status": "PREPARED",
                }
                state["in_flight_attempt"] = intent
                if not _persist_or_fail_closed(state, store, policy):
                    return state
            action_result = executor.act(deepcopy(decision), deepcopy(state))
            verification = executor.verify(deepcopy(action_result), deepcopy(state))
            receipt = None
            patch = verification.get("state_patch") if isinstance(verification, Mapping) else None
            # Validate the execution receipt and its durable lineage before
            # accepting any verifier-supplied state patch. Otherwise a rejected
            # receipt could still persist forged evidence refs or continuation data.
            if policy.require_execution_receipt:
                receipt = _validate_execution_receipt(verification)
                intent = state.get("in_flight_attempt")
                if not isinstance(intent, Mapping):
                    raise ValueError("durable execution intent is missing")
                if receipt.get("effect_id") != intent.get("effect_id") or receipt.get("attempt_id") != intent.get("attempt_id"):
                    raise ValueError("execution receipt lineage does not match persisted intent")
                if policy.execution_receipt_validator is not None:
                    policy.execution_receipt_validator(deepcopy(receipt), deepcopy(state))
            # UNKNOWN proves neither effect completion nor safe continuation. Keep
            # its receipt for reconciliation, but never let its state_patch promote
            # evidence refs or schedule another operation.
            if patch is not None and (
                not policy.require_execution_receipt
                or (receipt is not None and receipt.get("status") == "OBSERVED")
            ):
                _apply_state_patch(state, patch)
        except Exception as exc:
            state["status"] = policy.failure_state
            state["block_reason"] = f"execution failed after authorization: {type(exc).__name__}: {exc}"
            if not _persist_or_fail_closed(state, store, policy):

                return state
            return state
        state["step"] += 1
        state["history"].append({"step": state["step"], "observation": deepcopy(observation), "decision": deepcopy(decision), "action": deepcopy(action_result), "verification": deepcopy(verification)})
        # Only an OBSERVED receipt closes the prepared intent. UNKNOWN keeps it
        # durable for explicit reconciliation; it can never authorize a replay.
        if policy.require_execution_receipt and receipt is not None and receipt["status"] == "OBSERVED":
            state.pop("in_flight_attempt", None)
        # UNKNOWN is an unresolved side-effect boundary, not permission to retry.
        # Persist the attempt/receipt and stop until an explicit reconciliation authorizes continuation.
        if policy.require_execution_receipt and receipt is not None and receipt["status"] == "UNKNOWN":
            state["status"] = policy.failure_state
            state["block_reason"] = "UNKNOWN execution receipt; explicit reconciliation required before retry"
            if not _persist_or_fail_closed(state, store, policy):
                return state
            return state
        try:
            terminal = policy.terminal_evaluator(deepcopy(verification), deepcopy(state))
            if terminal == "PASS" and policy.acceptance_predicates:
                acceptance_input = dict(state)
                acceptance_input["verification"] = deepcopy(verification)
                evaluation = evaluate_acceptance(policy.acceptance_predicates, acceptance_input)
                failed = tuple(result for result in evaluation if not result.passed)
                if failed:
                    raise ValueError("PASS rejected: acceptance predicates failed: " + ", ".join(result.predicate_id for result in failed))
            if terminal is not None and terminal not in policy.terminal_states:
                raise ValueError(f"invalid terminal status: {terminal}")
            if policy.require_execution_receipt and receipt is not None and receipt["status"] == "UNKNOWN" and terminal is not None:
                raise ValueError("UNKNOWN execution receipt cannot authorize a terminal verdict")
            if policy.fix_plan is not None and terminal == policy.fix_success_state:
                _validate_fix_success(verification, terminal)
        except Exception as exc:
            state["status"] = policy.failure_state
            state["block_reason"] = f"terminal evaluation failed: {type(exc).__name__}: {exc}"
            if not _persist_or_fail_closed(state, store, policy):

                return state
            return state
        if terminal is not None:
            if terminal == "BLOCKED" and policy.blocked_continuation is not None:
                continuation = policy.blocked_continuation(deepcopy(verification), deepcopy(state))
                if continuation is not None:
                    if not isinstance(continuation, Mapping):
                        raise ValueError("blocked continuation must be a mapping")
                    required = ("authority", "evidence_refs", "next_operation_id", "reason")
                    missing = [k for k in required if k not in continuation]
                    if missing:
                        raise ValueError(f"blocked continuation missing fields: {missing}")
                    if not isinstance(continuation.get("evidence_refs"), list) or not continuation["evidence_refs"]:
                        raise ValueError("blocked continuation requires verified evidence refs")
                    if not all(isinstance(x, str) and x.strip() for x in continuation["evidence_refs"]):
                        raise ValueError("blocked continuation evidence refs are invalid")
                    if continuation.get("authority") != "AIOS_CONTROL_PLANE":
                        raise ValueError("blocked continuation authority is not AIOS_CONTROL_PLANE")
                    if not isinstance(continuation.get("next_operation_id"), str) or not continuation["next_operation_id"].strip():
                        raise ValueError("blocked continuation next operation is invalid")
                    next_operation = continuation["next_operation_id"]
                    if next_operation == "pcb.eda@1":
                        verified = set(state.get("verified_evidence_refs") or [])
                        if any(ref not in verified for ref in continuation["evidence_refs"]):
                            raise ValueError("pcb.eda redispatch requires persisted verified evidence refs")
                    elif next_operation != "pcb.eda.discover_evidence":
                        raise ValueError(f"unauthorized blocked continuation operation: {next_operation}")
                    state["status"] = "RUNNING"
                    state["continuation"] = deepcopy(dict(continuation))
                    state["history"][-1]["continuation"] = deepcopy(dict(continuation))
                    if not _persist_or_fail_closed(state, store, policy):

                        return state
                    continue
            state["status"] = terminal
            state["terminal_evidence"] = {
                "step": state["step"],
                "status": terminal,
                "verification": deepcopy(verification),
            }
            if not _persist_or_fail_closed(state, store, policy):

                return state
            return state
        state["status"] = "RUNNING"
        if not _persist_or_fail_closed(state, store, policy):

            return state
    state["status"] = policy.budget_exhaustion_state
    state["terminal_evidence"] = {
        "step": state["step"],
        "status": state["status"],
        "verification": {"reason": "BUDGET_EXHAUSTED"},
    }
    if not _persist_or_fail_closed(state, store, policy):

        return state
    return state


def reconcile_in_flight_attempt(
    store: StateStore,
    policy: LoopPolicy,
    receipt: Mapping[str, Any],
    *,
    authorizer: Callable[[Mapping[str, Any], Mapping[str, Any]], None],
) -> Mapping[str, Any]:
    """Close an interrupted attempt only with an authorized, matching OBSERVED receipt.

    This is the explicit recovery path for a crash after a provider effect but
    before its receipt was durably committed. It never guesses or retries.
    """
    if not callable(authorizer):
        raise ValueError("reconciliation requires an authority callback")
    loaded = store.load()
    if not isinstance(loaded, Mapping):
        raise ValueError("cannot reconcile without durable state")
    state = deepcopy(dict(loaded))
    _validate_loaded_state(state, policy)
    intent = state.get("in_flight_attempt")
    if not isinstance(intent, Mapping):
        raise ValueError("there is no in-flight execution attempt to reconcile")
    validated = _validate_execution_receipt({"receipt": receipt})
    if validated.get("status") != "OBSERVED":
        raise ValueError("reconciliation requires an OBSERVED provider receipt")
    if validated.get("effect_id") != intent.get("effect_id") or validated.get("attempt_id") != intent.get("attempt_id"):
        raise ValueError("reconciliation receipt does not match the persisted execution intent")
    authorizer(deepcopy(intent), deepcopy(validated))

    verification = {"status": "OBSERVED", "receipt": deepcopy(dict(validated)), "reconciled": True}
    history = state.get("history")
    if not isinstance(history, list):
        raise ValueError("durable history is invalid")
    already_recorded = bool(
        history
        and isinstance(history[-1], Mapping)
        and isinstance(history[-1].get("verification"), Mapping)
        and isinstance(history[-1]["verification"].get("receipt"), Mapping)
        and history[-1]["verification"]["receipt"].get("effect_id") == intent.get("effect_id")
        and history[-1]["verification"]["receipt"].get("attempt_id") == intent.get("attempt_id")
    )
    if already_recorded:
        history[-1]["verification"] = deepcopy(verification)
    else:
        state["step"] += 1
        history.append({
            "step": state["step"],
            "observation": deepcopy(intent.get("observation", {"reconciled": True})),
            "decision": deepcopy(intent.get("decision", {})),
            "action": {"effect_id": intent["effect_id"], "reconciled": True},
            "verification": deepcopy(verification),
        })
    state.pop("in_flight_attempt", None)
    state.pop("terminal_evidence", None)
    state.pop("block_reason", None)
    state["status"] = "RUNNING"

    try:
        terminal = policy.terminal_evaluator(deepcopy(verification), deepcopy(state))
        if terminal == "PASS" and policy.acceptance_predicates:
            acceptance_input = dict(state)
            acceptance_input["verification"] = deepcopy(verification)
            evaluation = evaluate_acceptance(policy.acceptance_predicates, acceptance_input)
            failed = tuple(result for result in evaluation if not result.passed)
            if failed:
                raise ValueError("PASS rejected: acceptance predicates failed: " + ", ".join(result.predicate_id for result in failed))
        if terminal is not None and terminal not in policy.terminal_states:
            raise ValueError(f"invalid terminal status: {terminal}")
        if policy.fix_plan is not None and terminal == policy.fix_success_state:
            _validate_fix_success(verification, terminal)
    except Exception as exc:
        state["status"] = policy.failure_state
        state["block_reason"] = f"reconciliation terminal evaluation failed: {type(exc).__name__}: {exc}"
        terminal = policy.failure_state

    if terminal is not None:
        state["status"] = terminal
        state["terminal_evidence"] = {
            "step": state["step"],
            "status": terminal,
            "verification": deepcopy(verification),
        }
    elif state["step"] >= policy.max_steps:
        state["status"] = policy.budget_exhaustion_state
        state["terminal_evidence"] = {
            "step": state["step"],
            "status": state["status"],
            "verification": {"reason": "BUDGET_EXHAUSTED_AFTER_RECONCILIATION"},
        }
    if not _persist_or_fail_closed(state, store, policy):
        return state
    return state

__all__ = ["TERMINAL", "LoopPolicy", "MemoryStateStore", "run_durable_loop", "reconcile_in_flight_attempt"]
