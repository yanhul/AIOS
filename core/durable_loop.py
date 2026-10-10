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
    # Appended to preserve positional compatibility for earlier LoopPolicy fields.
    state_patch_validator: Callable[[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]], None] | None = None

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
        if self.require_execution_receipt and self.execution_receipt_validator is None:
            raise ValueError(
                "require_execution_receipt requires an execution_receipt_validator; "
                "receipt shape and lineage do not establish provider authenticity"
            )
        if self.execution_receipt_validator is not None and not callable(self.execution_receipt_validator):
            raise ValueError("execution_receipt_validator must be callable")
        if self.require_execution_receipt and self.state_patch_validator is None:
            raise ValueError(
                "require_execution_receipt requires a state_patch_validator; "
                "an authentic receipt alone does not authorize arbitrary verifier state"
            )
        if self.state_patch_validator is not None and not callable(self.state_patch_validator):
            raise ValueError("state_patch_validator must be callable")
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
    # Effect and attempt identities are globally single-use within the durable
    # lineage. Validate the entire persisted history before any resumed action.
    seen_effect_ids: set[str] = set()
    seen_attempt_ids: set[str] = set()
    for index, entry in enumerate(state["history"]):
        if not isinstance(entry, Mapping):
            raise ValueError(f"persisted history entry is invalid at history[{index}]")
        verification = entry.get("verification")
        if policy.require_execution_receipt and not isinstance(verification, Mapping):
            raise ValueError(f"persisted verification is missing at history[{index}]")
        receipt = verification.get("receipt") if isinstance(verification, Mapping) else None
        if receipt is None:
            if policy.require_execution_receipt:
                raise ValueError(f"persisted execution receipt is missing at history[{index}]")
            continue
        if not isinstance(receipt, Mapping):
            raise ValueError(f"persisted receipt lineage is invalid at history[{index}]")
        effect_id = receipt.get("effect_id")
        attempt_id = receipt.get("attempt_id")
        if not isinstance(effect_id, str) or not effect_id.strip() or not isinstance(attempt_id, str) or not attempt_id.strip():
            raise ValueError(f"persisted receipt lineage is incomplete at history[{index}]")
        if receipt.get("status") not in {"OBSERVED", "UNKNOWN"}:
            raise ValueError(f"persisted receipt status is invalid at history[{index}]")
        if effect_id in seen_effect_ids:
            raise ValueError(f"duplicate persisted effect_id in history: {effect_id}")
        if attempt_id in seen_attempt_ids:
            raise ValueError(f"duplicate persisted attempt_id in history: {attempt_id}")
        seen_effect_ids.add(effect_id)
        seen_attempt_ids.add(attempt_id)
    in_flight = state.get("in_flight_attempt")
    if in_flight is not None:
        if not isinstance(in_flight, Mapping):
            raise ValueError("persisted in-flight execution attempt is invalid")
        effect_id = in_flight.get("effect_id")
        attempt_id = in_flight.get("attempt_id")
        if not isinstance(effect_id, str) or not effect_id.strip() or not isinstance(attempt_id, str) or not attempt_id.strip():
            raise ValueError("persisted in-flight execution lineage is incomplete")
        # An UNKNOWN receipt is intentionally retained in history while its
        # matching intent remains in-flight for explicit reconciliation. Permit
        # only that exact final-history pair; all other identity reuse blocks.
        last_receipt = None
        if state["history"]:
            last_entry = state["history"][-1]
            last_verification = last_entry.get("verification") if isinstance(last_entry, Mapping) else None
            candidate = last_verification.get("receipt") if isinstance(last_verification, Mapping) else None
            if isinstance(candidate, Mapping):
                last_receipt = candidate
        matching_unknown_in_flight = (
            isinstance(last_receipt, Mapping)
            and last_receipt.get("status") == "UNKNOWN"
            and last_receipt.get("effect_id") == effect_id
            and last_receipt.get("attempt_id") == attempt_id
        )
        if effect_id in seen_effect_ids and not matching_unknown_in_flight:
            raise ValueError(f"in-flight effect_id already exists in persisted history: {effect_id}")
        if attempt_id in seen_attempt_ids and not matching_unknown_in_flight:
            raise ValueError(f"in-flight attempt_id already exists in persisted history: {attempt_id}")
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
            authorization_result = policy.action_authorizer(deepcopy(decision), deepcopy(state))
            if authorization_result is not None:
                raise PermissionError("action_authorizer must return None or raise to deny")
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
                    validation_result = policy.execution_receipt_validator(deepcopy(receipt), deepcopy(state))
                    if validation_result is not None:
                        raise ValueError("execution_receipt_validator must return None or raise to reject")
            # UNKNOWN proves neither effect completion nor safe continuation. Keep
            # its receipt for reconciliation, but never let its state_patch promote
            # evidence refs or schedule another operation.
            if patch is not None and (
                not policy.require_execution_receipt
                or (receipt is not None and receipt.get("status") == "OBSERVED")
            ):
                if policy.require_execution_receipt:
                    if policy.state_patch_validator is None or receipt is None:
                        raise ValueError("state patch validation is not configured for receipt-governed execution")
                    patch_validation_result = policy.state_patch_validator(
                        deepcopy(patch), deepcopy(receipt), deepcopy(state)
                    )
                    if patch_validation_result is not None:
                        raise ValueError("state_patch_validator must return None or raise to reject")
                # Crash-safe receipt boundary: durably bind the validated provider
                # receipt and its validated patch to the in-flight attempt before
                # applying any patch. Recovery can then reconcile this exact attempt
                # without invoking the provider again.
                if policy.require_execution_receipt and receipt is not None and receipt.get("status") == "OBSERVED":
                    intent = deepcopy(dict(state["in_flight_attempt"]))
                    intent["status"] = "RECEIPT_VALIDATED"
                    intent["validated_receipt"] = deepcopy(dict(receipt))
                    intent["validated_state_patch"] = deepcopy(dict(patch or {}))
                    intent["validated_verification"] = deepcopy(dict(verification))
                    intent["validated_action_result"] = deepcopy(action_result)
                    state["in_flight_attempt"] = intent
                    if not _persist_or_fail_closed(state, store, policy):
                        return state
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
    # A receipt already committed as RECEIPT_VALIDATED is an exact durable
    # recovery token. Reject any altered copy before invoking validators or
    # authority callbacks, so tampering cannot trigger authorization side effects.
    pending_receipt = intent.get("validated_receipt")
    pending_patch = intent.get("validated_state_patch")
    pending_verification = intent.get("validated_verification")
    pending_action = intent.get("validated_action_result")
    if intent.get("status") == "RECEIPT_VALIDATED":
        if not isinstance(pending_receipt, Mapping) or dict(pending_receipt) != dict(validated):
            raise ValueError("reconciliation receipt does not match the durably validated receipt")
        if not isinstance(pending_patch, Mapping) or not isinstance(pending_verification, Mapping):
            raise ValueError("durable validated receipt record is incomplete")

    # Recovery must enforce the same provider/evidence validator as the normal
    # execution path. Shape and lineage alone do not prove the receipt is authentic.
    if policy.execution_receipt_validator is not None:
        validation_result = policy.execution_receipt_validator(deepcopy(validated), deepcopy(state))
        if validation_result is not None:
            raise ValueError("execution_receipt_validator must return None or raise to reject")
    authorization_result = authorizer(deepcopy(intent), deepcopy(validated))
    if authorization_result is not None:
        raise PermissionError("reconciliation authorizer must return None or raise to deny")

    # Revalidate the patch against the persisted receipt and current state,
    # then apply it during explicitly authorized recovery.
    if intent.get("status") == "RECEIPT_VALIDATED":
        if policy.state_patch_validator is None:
            raise ValueError("state patch validator is required to recover a validated receipt")
        patch_result = policy.state_patch_validator(deepcopy(dict(pending_patch)), deepcopy(validated), deepcopy(state))
        if patch_result is not None:
            raise ValueError("state_patch_validator must return None or raise to reject")
        _apply_state_patch(state, pending_patch)
        verification = deepcopy(dict(pending_verification))
        verification["receipt"] = deepcopy(dict(validated))
        verification["reconciled"] = True
    else:
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
            "action": deepcopy(pending_action) if intent.get("status") == "RECEIPT_VALIDATED" else {"effect_id": intent["effect_id"], "reconciled": True},
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
