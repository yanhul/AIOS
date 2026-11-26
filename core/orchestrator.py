"""Central governed execution bridge."""
from __future__ import annotations
import os
from copy import deepcopy
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping
from .acceptance import AcceptancePredicate
from .authority import authorize, load_contract
from .durable_loop import Executor, LoopPolicy, StateStore, _persist_state, reconcile_in_flight_attempt, run_durable_loop
from .effect_identity import verify_operation_identity
from .runtime import ProviderAdapter, execute

@dataclass(frozen=True)
class GovernedRuntimeExecutor(Executor):
    aios_dir: str
    contract_id: str
    permit_id: str
    actor: str
    adapter: ProviderAdapter
    observer: Callable[[Mapping[str, Any]], Any]
    decider: Callable[[Any, Mapping[str, Any]], Any]
    verifier: Callable[[Any, Mapping[str, Any]], Any]
    def observe(self, state: Mapping[str, Any]) -> Any: return self.observer(deepcopy(state))
    def decide(self, observation: Any, state: Mapping[str, Any]) -> Any: return self.decider(deepcopy(observation), deepcopy(state))
    def act(self, decision: Any, state: Mapping[str, Any]) -> Any:
        if not isinstance(decision, Mapping): raise ValueError("runtime decision must be a mapping")
        operation_id = decision.get("logical_operation_id")
        if not isinstance(operation_id, str) or not operation_id.strip(): raise ValueError("runtime decision must contain logical_operation_id")
        result = execute(self.aios_dir, self.contract_id, self.permit_id, operation_id, self.actor, self.adapter)
        if isinstance(result, Mapping) and "provider_observation" in result:
            return {**deepcopy(dict(result)), "evidence": deepcopy(result["provider_observation"])}
        return result
    def verify(self, action_result: Any, state: Mapping[str, Any]) -> Any: return self.verifier(deepcopy(action_result), deepcopy(state))

def run_governed_execution(*, executor: GovernedRuntimeExecutor, store: StateStore, policy: LoopPolicy) -> Mapping[str, Any]:
    """Run/resume the single AIOS durable loop with authority-bound state."""
    authorize(executor.aios_dir, executor.contract_id, executor.permit_id)
    contract = load_contract(executor.aios_dir, executor.contract_id)
    if policy.policy_digest != contract["policy_digest"]:
        raise PermissionError("execution policy digest does not match governing contract")
    if policy.max_steps > contract["max_attempts"]:
        raise PermissionError("execution budget exceeds governing contract max_attempts")
    governing_terminal_states = frozenset(contract["terminal_states"])
    if not governing_terminal_states:
        raise PermissionError("governing execution must define terminal states")
    if policy.terminal_states != governing_terminal_states:
        raise PermissionError("execution terminal states do not match governing contract")
    if policy.failure_state not in governing_terminal_states:
        raise PermissionError("execution failure state is not authorized by governing contract")
    if policy.budget_exhaustion_state not in governing_terminal_states:
        raise PermissionError("budget exhaustion state is not authorized by governing contract")

    # Acceptance predicates are contract-bound authority: the loop must enforce
    # exactly the predicates the permit was issued for, never fewer or others.
    governing_predicates = tuple(
        AcceptancePredicate(predicate_id=p["predicate_id"], path=p["path"],
                            operator=p["operator"], expected=p.get("expected"))
        for p in contract.get("acceptance_predicates", []))
    if tuple(policy.acceptance_predicates) != governing_predicates:
        raise PermissionError("execution acceptance predicates do not match governing contract")

    caller_resume_validator = policy.resume_validator

    def validate_resume(state: Mapping[str, Any]) -> None:
        if state.get("contract_id") != executor.contract_id: raise ValueError("persisted contract binding does not match execution context")
        if state.get("permit_id") != executor.permit_id: raise ValueError("persisted permit binding does not match execution context")
        authorize(executor.aios_dir, executor.contract_id, executor.permit_id)
        if caller_resume_validator is not None: caller_resume_validator(state)

    # replace() forwards every LoopPolicy field (receipt gates, fix plan,
    # acceptance, continuation, state-patch validation); only authority-bound
    # fields are overridden from the governing contract.
    bound_policy = replace(
        policy,
        resume_validator=validate_resume,
        policy_digest=contract["policy_digest"],
        terminal_states=governing_terminal_states,
        acceptance_predicates=governing_predicates,
        operation_identity=_governed_operation_identity(executor),
    )
    loaded = store.load()
    if loaded is None:
        store.save({"contract_id": executor.contract_id, "permit_id": executor.permit_id, "policy_digest": bound_policy.policy_digest})
    else:
        state = deepcopy(dict(loaded))
        if state.get("contract_id") != executor.contract_id or state.get("permit_id") != executor.permit_id:
            return _block(store, state, bound_policy, "BINDING_MISMATCH",
                          "persisted execution binding does not match current authority context")
        if bound_policy.require_execution_receipt and state.get("in_flight_attempt") is not None:
            reconciled = reconcile_with_ledger(executor=executor, store=store, policy=bound_policy)
            if reconciled.get("status") != "RUNNING":
                return reconciled
    return run_durable_loop(executor, store, bound_policy)


def _governed_operation_identity(executor: GovernedRuntimeExecutor):
    """Decision A: identity = (governing contract, decision's logical operation, executor actor)."""
    def identity(decision: Any, state: Mapping[str, Any]) -> Mapping[str, str]:
        if not isinstance(decision, Mapping):
            raise ValueError("runtime decision must be a mapping")
        return {"contract_id": executor.contract_id, "actor": executor.actor,
                "logical_operation_id": decision.get("logical_operation_id")}
    return identity


def _block(store: StateStore, state: dict, policy: LoopPolicy, classification: str, detail: str) -> Mapping[str, Any]:
    state["status"] = policy.failure_state
    state["block_reason"] = f"L5_RECONCILIATION {classification}: {detail}"
    state["reconciliation"] = {"classification": classification, "detail": detail}
    state["terminal_evidence"] = {"step": state.get("step", 0), "status": policy.failure_state,
                                  "verification": {"reason": state["block_reason"]}}
    # Persist through the canonical path so the continue_contract projection is
    # rebuilt from the BLOCKED state (never a stale RUNNING projection). If the
    # projection cannot be built, drop it rather than persist a contradiction;
    # restart then fails closed on the missing projection. In-flight intent is kept.
    try:
        _persist_state(state, store, policy)
    except Exception as exc:  # noqa: BLE001
        state.pop("continue_contract", None)
        state["projection_error"] = f"{type(exc).__name__}: {exc}"
        store.save(deepcopy(state))
    return state


def reconcile_with_ledger(*, executor: GovernedRuntimeExecutor, store: StateStore, policy: LoopPolicy) -> Mapping[str, Any]:
    """Restart path: reconcile the persisted L3 intent against the L5 ledger. Never dispatches.

    OBSERVED_* with valid identity/ledger/receipt lineage -> closed through the
    existing reconcile_in_flight_attempt (same validators). Everything else is
    BLOCKED with a classification; nothing is inferred or backfilled.
    """
    from .effect_authority import _load, _path, recover_pending, verify_effect_ledger
    state = deepcopy(dict(store.load() or {}))
    intent = state.get("in_flight_attempt")
    if not isinstance(intent, Mapping) or "identity_version" not in intent:
        return _block(store, state, policy, "LEGACY_UNRECONCILED",
                      "in-flight intent has no canonical operation identity (random IDs)")
    try:
        verify_operation_identity(intent)
    except ValueError as exc:
        return _block(store, state, policy, "IDENTITY_INVALID", str(exc))
    decision = intent.get("decision")
    if (intent["contract_id"], intent["actor"]) != (executor.contract_id, executor.actor) or not isinstance(
            decision, Mapping) or decision.get("logical_operation_id") != intent["logical_operation_id"]:
        return _block(store, state, policy, "IDENTITY_MISMATCH",
                      "intent contract/actor/decision does not match the governed execution context")
    try:  # explicit, separate L5 journal recovery; verification below is read-only
        recover_pending(executor.aios_dir)
    except Exception as exc:  # noqa: BLE001
        return _block(store, state, policy, "LEDGER_RECOVERY_BLOCKED", f"{type(exc).__name__}: {exc}")
    effect_path = _path(executor.aios_dir, intent["effect_id"])
    if not os.path.exists(effect_path):
        return _block(store, state, policy, "LEDGER_MISSING_EFFECT",
                      "no L5 effect for this logical operation; not inferring whether the provider ran")
    effect = _load(effect_path)
    expected = {"effect_id": intent["effect_id"], "contract_id": intent["contract_id"], "actor": intent["actor"],
                "logical_operation_id": intent["logical_operation_id"], "permit_id": executor.permit_id}
    if any(effect.get(k) != v for k, v in expected.items()):
        return _block(store, state, policy, "LEDGER_IDENTITY_MISMATCH", "L5 effect identity differs from the intent")
    try:
        ledger = verify_effect_ledger(executor.aios_dir, intent["effect_id"])
    except Exception as exc:  # noqa: BLE001 - any ledger failure is fail-closed
        return _block(store, state, policy, "LEDGER_INCONSISTENT", f"{type(exc).__name__}: {exc}")
    if ledger.get("verdict") not in ("VERIFIED", "VERIFIED_SEPARATE"):
        return _block(store, state, policy, "LEDGER_UNVERIFIABLE", f"{ledger.get('verdict')}:{ledger.get('status')}")
    if effect.get("state") not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        return _block(store, state, policy, f"LEDGER_{effect.get('state')}",
                      "effect outcome is not observed; no automatic dispatch or promotion")
    if effect.get("attempt_id") != intent["attempt_id"]:
        return _block(store, state, policy, "ATTEMPT_MISMATCH", "observed attempt differs from the intent attempt")
    try:
        authorize(executor.aios_dir, executor.contract_id, executor.permit_id)
        action_result = {**deepcopy(effect), "evidence": deepcopy(effect["provider_observation"])}
        verification = executor.verify(action_result, deepcopy(state))
        receipt = verification.get("receipt") if isinstance(verification, Mapping) else None
        if not isinstance(receipt, Mapping) or receipt.get("status") != "OBSERVED" or (
                receipt.get("effect_id"), receipt.get("attempt_id")) != (intent["effect_id"], intent["attempt_id"]):
            return _block(store, state, policy, "RECEIPT_MISMATCH",
                          "verifier receipt does not bind the observed L5 effect/attempt")

        def ledger_authorizer(pending: Mapping[str, Any], validated: Mapping[str, Any]) -> None:
            if (validated.get("effect_id"), validated.get("attempt_id")) != (effect["effect_id"], effect["attempt_id"]):
                raise PermissionError("receipt does not match the L5 ledger")
            authorize(executor.aios_dir, executor.contract_id, executor.permit_id)
        return reconcile_in_flight_attempt(store, policy, dict(receipt), authorizer=ledger_authorizer,
                                           verification=verification, action_result=action_result)
    except Exception as exc:  # noqa: BLE001
        return _block(store, deepcopy(dict(store.load() or state)), policy, "RECONCILIATION_REJECTED",
                      f"{type(exc).__name__}: {exc}")

__all__ = ["GovernedRuntimeExecutor", "reconcile_with_ledger", "run_governed_execution"]
