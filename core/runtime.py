"""Thin AIOS provider boundary.

AIOS owns authority and evidence semantics. Durable scheduling, retries,
resume, planning and agent loops belong to an external execution substrate.
"""

from dataclasses import dataclass
from typing import Protocol

from .authority import authorize, load_contract, load_permit
from .durable_runtime import DurableRuntime, validate_submission
from .effect_authority import create_effect, dispatch, observe, retry_dispatch, unknown


@dataclass(frozen=True)
class ProviderReceipt:
    """Immutable provider receipt at the AIOS/Gateway receipt boundary."""
    provider: str
    effect_id: str
    attempt_id: str
    provider_operation_id: str
    outcome: str
    observation: dict
    target_sha: str
    evidence_ref: str
    lineage_ref: str
    idempotency_key: str
    attempt_fence: int


class ProviderAdapter(Protocol):
    name: str

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        """Execute exactly one already-authorized provider operation."""
        ...


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _provider_authorized(contract, provider_name):
    return any(
        isinstance(ref, str) and ref.split("@", 1)[0] == provider_name
        for ref in contract.get("capabilities", [])
    )


def _submit_runtime(runtime, method, effect, attempt_id, provider_name, **kwargs):
    """Bridge an already-authorized attempt into an external durable runtime."""
    if runtime is None:
        return None
    if not hasattr(runtime, method):
        raise ValueError(f"durable runtime must implement {method}")
    submission = getattr(runtime, method)(effect=dict(effect), attempt_id=attempt_id, **kwargs)
    validate_submission(effect, submission, attempt_id, provider_name)
    return submission


def validate_receipt(receipt, effect, attempt_id, provider_name):
    """Fail closed unless the provider returned a complete, bound receipt."""
    if not isinstance(receipt, ProviderReceipt):
        raise ValueError("provider must return ProviderReceipt")
    _text(receipt.provider, "receipt.provider")
    _text(receipt.effect_id, "receipt.effect_id")
    _text(receipt.attempt_id, "receipt.attempt_id")
    _text(receipt.provider_operation_id, "receipt.provider_operation_id")
    _text(receipt.target_sha, "receipt.target_sha")
    _text(receipt.evidence_ref, "receipt.evidence_ref")
    _text(receipt.lineage_ref, "receipt.lineage_ref")
    _text(receipt.idempotency_key, "receipt.idempotency_key")

    if "target_sha" not in effect:
        raise ValueError("effect target_sha is required before execution")
    if "attempt_fence" not in effect:
        raise ValueError("effect attempt_fence is required before execution")
    expected_target_sha = _text(effect["target_sha"], "effect.target_sha")
    expected_fence = effect["attempt_fence"]
    if not isinstance(expected_fence, int) or isinstance(expected_fence, bool) or expected_fence < 0:
        raise ValueError("effect attempt_fence must be a non-negative integer")
    if not isinstance(receipt.attempt_fence, int) or isinstance(receipt.attempt_fence, bool):
        raise ValueError("receipt.attempt_fence must be an integer")
    if receipt.attempt_fence < 0:
        raise ValueError("receipt.attempt_fence must be non-negative")
    if receipt.effect_id != effect["effect_id"]:
        raise ValueError("receipt effect binding mismatch")
    if receipt.attempt_id != attempt_id:
        raise ValueError("receipt attempt binding mismatch")
    if receipt.provider != provider_name:
        raise ValueError("receipt provider binding mismatch")
    if receipt.target_sha != expected_target_sha:
        raise ValueError("receipt target_sha binding mismatch")
    if receipt.attempt_fence != expected_fence:
        raise ValueError("receipt attempt_fence binding mismatch")
    for field in ("evidence_ref", "lineage_ref", "idempotency_key"):
        if field not in effect:
            raise ValueError(f"effect {field} is required before execution")
        expected = _text(effect[field], f"effect.{field}")
        if getattr(receipt, field) != expected:
            raise ValueError(f"receipt {field} binding mismatch")
    if receipt.outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("receipt outcome must be an observed terminal outcome")
    if not isinstance(receipt.observation, dict) or not receipt.observation:
        raise ValueError("receipt observation must be a non-empty dict")
    evidence = receipt.observation.get("evidence")
    if not isinstance(evidence, dict) or not evidence:
        raise ValueError("receipt observation requires a valid evidence record")
    if evidence.get("evidence_id") != effect["evidence_ref"]:
        raise ValueError("receipt evidence identity binding mismatch")


def execute_attempt(aios_dir, contract, effect, actor, adapter, attempt_id):
    """Execute exactly one dispatched attempt and record its observation."""
    _text(actor, "actor")
    _text(attempt_id, "attempt_id")
    if not isinstance(contract, dict) or not contract:
        raise ValueError("contract must be a non-empty dict")
    if not isinstance(effect, dict) or not effect:
        raise ValueError("effect must be a non-empty dict")
    if effect.get("state") != "DISPATCHED":
        raise RuntimeError("effect must be DISPATCHED before execute_attempt")
    if effect.get("actor") != actor:
        raise PermissionError("effect actor does not match execution actor")
    if effect.get("attempt_id") != attempt_id:
        raise RuntimeError("attempt_id does not match dispatched effect")
    if not hasattr(adapter, "name"):
        raise ValueError("adapter must expose a provider name")
    provider_name = _text(adapter.name, "adapter.name")
    if not _provider_authorized(contract, provider_name):
        raise PermissionError("provider capability is not authorized by contract")
    if "external_effect" not in contract.get("allowed_effects", []):
        raise PermissionError("external effect is not authorized by contract")

    try:
        receipt = adapter.execute(contract=dict(contract), effect=dict(effect), attempt_id=attempt_id)
    except Exception as exc:
        return unknown(
            aios_dir,
            effect["effect_id"],
            actor,
            f"provider ambiguity: {type(exc).__name__}: {exc}",
        )

    # Gate 1: receipt integrity/binding failure MUST NOT be converted to UNKNOWN.
    validate_receipt(receipt, effect, attempt_id, provider_name)

    provider_observation = {
        "provider": receipt.provider,
        "provider_operation_id": receipt.provider_operation_id,
        "effect_id": receipt.effect_id,
        "attempt_id": receipt.attempt_id,
        "target_sha": receipt.target_sha,
        "evidence_ref": receipt.evidence_ref,
        "lineage_ref": receipt.lineage_ref,
        "idempotency_key": receipt.idempotency_key,
        "attempt_fence": receipt.attempt_fence,
        "observation": receipt.observation,
        "evidence": receipt.observation["evidence"],
    }
    return observe(aios_dir, effect["effect_id"], actor, receipt.outcome, provider_observation)


def execute_retry_attempt(aios_dir, contract_id, permit_id, effect, actor, adapter, attempt_id, attempt,
                          target_sha, attempt_fence, durable_runtime: DurableRuntime | None = None):
    """Authorize, dispatch and execute one explicit retry of an UNKNOWN effect."""
    _text(actor, "actor")
    _text(attempt_id, "attempt_id")
    if not isinstance(effect, dict) or not effect:
        raise ValueError("effect must be a non-empty dict")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    if effect.get("contract_id") != contract_id:
        raise PermissionError("effect contract binding mismatch")
    if effect.get("actor") != actor:
        raise PermissionError("effect actor does not match effect owner")
    if effect.get("state") != "UNKNOWN":
        raise RuntimeError("effect must be UNKNOWN before retry")
    authorize(aios_dir, contract_id, permit_id)
    contract = load_contract(aios_dir, contract_id)
    permit = load_permit(aios_dir, permit_id)
    if permit["actor"] != actor or contract["actor"] != actor:
        raise PermissionError("actor does not match authorized contract")
    max_attempts = contract.get("max_attempts")
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise ValueError("contract max_attempts must be a positive integer")
    if attempt > max_attempts:
        raise PermissionError("retry exceeds contract max_attempts")
    provider_name = _text(getattr(adapter, "name", None), "adapter.name")
    if not _provider_authorized(contract, provider_name):
        raise PermissionError("provider capability is not authorized by contract")
    if "external_effect" not in contract["allowed_effects"]:
        raise PermissionError("external effect is not authorized by contract")
    dispatched = retry_dispatch(aios_dir, effect["effect_id"], actor, attempt_id, provider_name, attempt,
                                target_sha=target_sha, attempt_fence=attempt_fence)
    _submit_runtime(durable_runtime, "retry", dispatched, attempt_id, provider_name, attempt=attempt)
    return execute_attempt(aios_dir, contract, dispatched, actor, adapter, attempt_id)


def execute(aios_dir, contract_id, permit_id, logical_operation_id, actor, adapter,
            target_sha, evidence_ref, lineage_ref, idempotency_key, attempt_fence,
            durable_runtime: DurableRuntime | None = None):
    """Authorize/create/dispatch the first attempt with an external Gateway binding."""
    _text(logical_operation_id, "logical_operation_id")
    _text(actor, "actor")
    if not hasattr(adapter, "name"):
        raise ValueError("adapter must expose a provider name")
    provider_name = _text(adapter.name, "adapter.name")
    authorize(aios_dir, contract_id, permit_id)
    contract = load_contract(aios_dir, contract_id)
    permit = load_permit(aios_dir, permit_id)
    if permit["actor"] != actor or contract["actor"] != actor:
        raise PermissionError("actor does not match authorized contract")
    if not _provider_authorized(contract, provider_name):
        raise PermissionError("provider capability is not authorized by contract")
    if "external_effect" not in contract["allowed_effects"]:
        raise PermissionError("external effect is not authorized by contract")
    effect = create_effect(aios_dir, contract_id, logical_operation_id, actor, permit_id, "external_effect")
    if effect["state"] != "PLANNED":
        raise RuntimeError("logical operation already has a non-planned effect")
    attempt_id = f"{effect['effect_id']}:attempt:1"
    effect = dispatch(aios_dir, effect["effect_id"], actor, attempt_id, provider_name,
                      target_sha=target_sha, evidence_ref=evidence_ref,
                      lineage_ref=lineage_ref, idempotency_key=idempotency_key,
                      attempt_fence=attempt_fence)
    _submit_runtime(durable_runtime, "submit", effect, attempt_id, provider_name)
    return execute_attempt(aios_dir, contract, effect, actor, adapter, attempt_id)


__all__ = [
    "ProviderReceipt", "ProviderAdapter", "validate_receipt",
    "execute_attempt", "execute_retry_attempt", "execute",
]
