"""Central governed execution bridge."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import inspect
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping
from .acceptance import AcceptancePredicate
from .authority import authorize, load_contract
from .durable_loop import Executor, LoopPolicy, StateStore, run_durable_loop
from .runtime import ProviderAdapter, execute
from .policy_registry import resolve_policy

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


def _validator_identity(callback: Callable[..., Any], role: str) -> dict[str, str]:
    """Describe the actual host callback implementation for durable audit.

    This is provenance, not authentication: Python host code is the declared
    trust boundary. The deployment digest is supplied by deployment tooling.
    """
    module = getattr(callback, "__module__", None)
    qualname = getattr(callback, "__qualname__", None)
    if not isinstance(module, str) or not module or not isinstance(qualname, str) or not qualname:
        raise PermissionError(f"{role} must expose a stable module and qualified name")
    try:
        source_file = inspect.getsourcefile(callback) or inspect.getfile(callback)
        with open(source_file, "rb") as handle:
            source_file_digest = "sha256:" + hashlib.sha256(handle.read()).hexdigest()
        implementation = inspect.getsource(callback)
        implementation_digest = "sha256:" + hashlib.sha256(implementation.encode("utf-8")).hexdigest()
    except (OSError, TypeError) as exc:
        raise PermissionError(f"{role} source implementation cannot be fingerprinted") from exc
    return {
        "role": role, "module": module, "qualified_name": qualname,
        "implementation_digest": implementation_digest,
        "source_file_digest": source_file_digest,
    }


def _build_validator_provenance(policy: LoopPolicy) -> dict[str, Any]:
    if not policy.deployment_id or not policy.deployment_id.strip():
        raise PermissionError("receipt-governed execution requires deployment_id from trusted host integration")
    digest = policy.deployment_digest
    if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:") or any(c not in "0123456789abcdef" for c in digest[7:]):
        raise PermissionError("receipt-governed execution requires canonical deployment_digest from trusted host integration")
    if policy.execution_receipt_validator is None or policy.state_patch_validator is None:
        raise ValueError("receipt-governed execution requires an execution_receipt_validator and state_patch_validator")
    return {
        "schema": "AIOS_VALIDATOR_PROVENANCE_V1",
        "deployment_id": policy.deployment_id,
        "deployment_digest": digest,
        "validators": [
            _validator_identity(policy.execution_receipt_validator, "execution_receipt_validator"),
            _validator_identity(policy.state_patch_validator, "state_patch_validator"),
        ],
        "trust_boundary": "TRUSTED_PYTHON_HOST",
        "authentication_scope": "AUDIT_ONLY_NOT_IN_PROCESS_CALLER_AUTHENTICATION",
    }


def run_governed_execution(*, executor: GovernedRuntimeExecutor, store: StateStore, policy: LoopPolicy) -> Mapping[str, Any]:
    """Run/resume the single AIOS durable loop with authority-bound state."""
    authorize(executor.aios_dir, executor.contract_id, executor.permit_id)
    contract = load_contract(executor.aios_dir, executor.contract_id)
    if policy.policy_digest != contract["policy_digest"]:
        raise PermissionError("execution policy digest does not match governing contract")
    try:
        governing_policy = resolve_policy(executor.aios_dir, contract["policy_digest"])
    except ValueError as exc:
        raise PermissionError(f"governing policy could not be resolved: {exc}") from exc
    missing_policy_fields = {"require_execution_receipt", "acceptance_predicates"} - set(governing_policy)
    if missing_policy_fields:
        raise PermissionError(
            "governing policy lacks explicit runtime enforcement declarations: "
            + ", ".join(sorted(missing_policy_fields))
        )
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

    # Acceptance criteria are authority-owned contract data, not caller-owned
    # runtime options. Derive the effective predicates from the loaded contract;
    # reject conflicting caller configuration rather than silently weakening it.
    policy_predicates = tuple(
        AcceptancePredicate.from_mapping(raw)
        for raw in governing_policy.get("acceptance_predicates", ())
    )
    contract_predicates = tuple(
        AcceptancePredicate.from_mapping(raw)
        for raw in contract.get("acceptance_predicates", ())
    )
    if contract_predicates != policy_predicates:
        raise PermissionError(
            "execution contract acceptance predicates do not match governing policy artifact"
        )
    if policy.acceptance_predicates and policy.acceptance_predicates != policy_predicates:
        raise PermissionError("execution acceptance predicates do not match governing policy")
    # The content-addressed policy, not the caller's LoopPolicy, owns whether
    # receipt enforcement is mandatory. Stronger caller enforcement is allowed;
    # caller weakening is impossible. LoopPolicy construction then fails closed
    # if trusted validator implementations are not supplied. Validator callbacks
    # are executable host-integration code, never policy JSON or model output.
    require_execution_receipt = (
        policy.require_execution_receipt
        or governing_policy.get("require_execution_receipt", False)
    )

    def validate_resume(state: Mapping[str, Any]) -> None:
        if state.get("contract_id") != executor.contract_id: raise ValueError("persisted contract binding does not match execution context")
        if state.get("permit_id") != executor.permit_id: raise ValueError("persisted permit binding does not match execution context")
        authorize(executor.aios_dir, executor.contract_id, executor.permit_id)

    # dataclasses.replace preserves every LoopPolicy control (receipt and state
    # patch validators, fix plan, acceptance gates, continuation callbacks,
    # and future fields) while replacing only authority-bound values.
    validator_provenance = _build_validator_provenance(policy) if require_execution_receipt else None
    bound_policy = replace(
        policy,
        resume_validator=validate_resume,
        policy_digest=contract["policy_digest"],
        terminal_states=governing_terminal_states,
        acceptance_predicates=policy_predicates,
        require_execution_receipt=require_execution_receipt,
        validator_provenance=validator_provenance,
    )
    loaded = store.load()
    if loaded is None:
        store.save({"contract_id": executor.contract_id, "permit_id": executor.permit_id, "policy_digest": bound_policy.policy_digest})
    else:
        state = deepcopy(dict(loaded))
        if state.get("contract_id") != executor.contract_id or state.get("permit_id") != executor.permit_id:
            state["status"] = bound_policy.failure_state
            state["block_reason"] = "persisted execution binding does not match current authority context"
            store.save(state)
            return state
    return run_durable_loop(executor, store, bound_policy)

__all__ = ["GovernedRuntimeExecutor", "run_governed_execution"]