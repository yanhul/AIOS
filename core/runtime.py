"""Thin AIOS provider boundary.

AIOS owns authority and evidence semantics. Durable scheduling, retries,
resume, planning and agent loops belong to an external execution substrate.
"""

from dataclasses import dataclass
from typing import Protocol

from .authority import authorize, load_contract, load_permit
from .effect_authority import create_effect, dispatch, observe, unknown


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


def validate_receipt(receipt, effect, attempt_id, provider_name):
    """Fail closed unless the provider explicitly observed a bound outcome."""
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


def execute(aios_dir, contract_id, permit_id, logical_operation_id, actor, adapter):
    """Execute one bounded attempt; orchestration remains outside AIOS."""
    _text(logical_operation_id, "logical_operation_id")
    _text(actor, "actor")
    if not hasattr(adapter, "name"):
        raise ValueError("adapter must expose a provider name")
    provider_name = _text(adapter.name, "adapter.name")

    # No provider call is possible before these checks complete.
    authorize(aios_dir, contract_id, permit_id)
    contract = load_contract(aios_dir, contract_id)
    permit = load_permit(aios_dir, permit_id)
    if permit["actor"] != actor or contract["actor"] != actor:
        raise PermissionError("actor does not match authorized contract")
    if provider_name not in contract["capabilities"]:
        raise PermissionError("provider capability is not authorized by contract")
    if "external_effect" not in contract["allowed_effects"]:
        raise PermissionError("external effect is not authorized by contract")

    effect = create_effect(aios_dir, contract_id, logical_operation_id, actor)
    if effect["state"] != "PLANNED":
        raise RuntimeError("logical operation already has a non-planned effect")

    # Attempt sequencing/retry policy belongs to the durable substrate. This
    # boundary executes one attempt and never invents a second one locally.
    attempt_id = f"{effect['effect_id']}:attempt:1"
    dispatch(aios_dir, effect["effect_id"], actor, attempt_id, provider_name)
    try:
        receipt = adapter.execute(
            contract=dict(contract), effect=dict(effect), attempt_id=attempt_id
        )
        validate_receipt(receipt, effect, attempt_id, provider_name)
    except Exception as exc:
        return unknown(
            aios_dir,
            effect["effect_id"],
            actor,
            f"provider ambiguity: {type(exc).__name__}: {exc}",
        )

    return observe(
        aios_dir,
        effect["effect_id"],
        actor,
        receipt.outcome,
        {
            "provider": receipt.provider,
            "provider_operation_id": receipt.provider_operation_id,
            "effect_id": receipt.effect_id,
            "attempt_id": receipt.attempt_id,
            "observation": receipt.observation,
        },
    )


__all__ = ["ProviderReceipt", "ProviderAdapter", "validate_receipt", "execute"]
