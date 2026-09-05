"""Thin AIOS provider boundary.

AIOS owns authority and evidence semantics. Durable scheduling, retries,
resume, planning and agent loops belong to an external execution substrate.
"""

from dataclasses import dataclass
from typing import Protocol

from .authority import authorize, load_contract, load_permit
from .durable_runtime import DurableRuntime, validate_submission
from .effect_authority import (
    begin_dispatch,
    begin_retry_dispatch,
    create_effect,
    mark_dispatched,
    observe,
    unknown,
)


@dataclass(frozen=True)
class ProviderReceipt:
    provider: str
    effect_id: str
    attempt_id: str
    provider_operation_id: str
    outcome: str
    observation: dict


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
    return any(isinstance(ref, str) and ref.split("@", 1)[0] == provider_name
               for ref in contract.get("capabilities", []))


def _submit_runtime(runtime, method, effect, attempt_id, provider_name, **kwargs):
    if runtime is None:
        return None
    if not hasattr(runtime, method):
        raise ValueError(f"durable runtime must implement {method}")
    submission = getattr(runtime, method)(effect=dict(effect), attempt_id=attempt_id, **kwargs)
    validate_submission(effect, submission, attempt_id, provider_name)
    return submission


def validate_receipt(receipt, effect, attempt_id, provider_name):
    if not isinstance(receipt, ProviderReceipt):
        raise ValueError("provider must return ProviderReceipt")
    _text(receipt.provider, "receipt.provider")
    _text(receipt.effect_id, "receipt.effect_id")
    _text(receipt.attempt_id, "receipt.attempt_id")
    _text(receipt.provider_operation_id, "receipt.provider_operation_id")
    if receipt.effect_id != effect["effect_id"]:
        raise ValueError("receipt effect binding mismatch")
    if receipt.attempt_id != attempt_id:
        raise ValueError("receipt attempt binding mismatch")
    if receipt.provider != provider_name:
        raise ValueError("receipt provider binding mismatch")
    if receipt.outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("receipt outcome must be an observed terminal outcome")
    if not isinstance(receipt.observation, dict) or not receipt.observation:
        raise ValueError("receipt observation must be a non-empty dict")


def execute_attempt(aios_dir, contract, effect, actor, adapter, attempt_id):
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
        validate_receipt(receipt, effect, attempt_id, provider_name)
    except Exception as exc:
        return unknown(aios_dir, effect["effect_id"], actor,
                       f"provider ambiguity: {type(exc).__name__}: {exc}")

    return observe(aios_dir, effect["effect_id"], actor, receipt.outcome, {
        "provider": receipt.provider,
        "provider_operation_id": receipt.provider_operation_id,
        "effect_id": receipt.effect_id,
        "attempt_id": receipt.attempt_id,
        "observation": receipt.observation,
    })


def execute_retry_attempt(aios_dir, contract_id, permit_id, effect, actor, adapter, attempt_id, attempt,
                          durable_runtime: DurableRuntime | None = None):
    """Authorize, journal and execute one explicit retry of an UNKNOWN effect."""
    _text(actor, "actor")
    _text(attempt_id, "attempt_id")
    if not isinstance(effect, dict) or not effect:
        raise ValueError("effect must be a non-empty dict")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    if effect.get("contract_id") != contract_id:
        raise PermissionError("effect contract binding mismatch")
    if effect.get("actor") != actor:
        raise PermissionError("effect actor does not match execution actor")
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

    dispatched = begin_retry_dispatch(aios_dir, effect["effect_id"], actor, attempt_id, provider_name, attempt)
    _submit_runtime(durable_runtime, "retry", dispatched, attempt_id, provider_name, attempt=attempt)
    dispatched = mark_dispatched(aios_dir, effect["effect_id"], actor)
    return execute_attempt(aios_dir, contract, dispatched, actor, adapter, attempt_id)


def execute(aios_dir, contract_id, permit_id, logical_operation_id, actor, adapter,
            durable_runtime: DurableRuntime | None = None):
    """Authorize/create/journal the first attempt, then delegate execution."""
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

    effect = create_effect(aios_dir, contract_id, logical_operation_id, actor)
    if effect["state"] != "PLANNED":
        raise RuntimeError("logical operation already has a non-planned effect")
    attempt_id = f"{effect['effect_id']}:attempt:1"
    effect = begin_dispatch(aios_dir, effect["effect_id"], actor, attempt_id, provider_name)
    _submit_runtime(durable_runtime, "submit", effect, attempt_id, provider_name)
    effect = mark_dispatched(aios_dir, effect["effect_id"], actor)
    return execute_attempt(aios_dir, contract, effect, actor, adapter, attempt_id)
