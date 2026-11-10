"""Compatibility facade for the authoritative M6 external-effect boundary.

Legacy helpers remain available, but they no longer invent a privileged
``legacy-external-effect`` actor. Callers must provide the real contract actor,
permit, and authorized effect type; all writes then flow through the single
M6 authority/evidence state machine.
"""

import os

from .effect_authority import _load_current as _load_current_effect
from .effect_authority import create_effect as _create_effect
from .effect_authority import dispatch as _dispatch
from .effect_authority import observe as _observe
from .effect_authority import unknown as _unknown
from .mutation import MutationError, TransitionError


class ExternalEffectError(MutationError):
    pass


def create_effect(aios_dir, contract_id, logical_operation_id, actor, permit_id, effect_type):
    try:
        return _create_effect(aios_dir, contract_id, logical_operation_id, actor, permit_id, effect_type)
    except (ValueError, KeyError, TransitionError) as exc:
        raise ExternalEffectError(str(exc)) from exc


def load_effects(aios_dir):
    """Load only effects that pass the authoritative persisted-record checks.

    The effects directory is writable state, not an authority source. Never
    expose raw JSON records here: validate each record against its filename,
    contract, permit, provider capability, attempt identity and receipt.
    """
    out = {}
    d = os.path.join(aios_dir, "effects")
    if not os.path.isdir(d):
        return out
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".json"):
            continue
        effect_id = fn[:-5]
        try:
            rec = _load_current_effect(aios_dir, effect_id)
        except (OSError, ValueError, KeyError, TransitionError) as exc:
            raise ExternalEffectError(
                f"persisted external effect {effect_id!r} failed authority validation: {exc}"
            ) from exc
        if rec.get("record_type") == "EXTERNAL_EFFECT":
            out[effect_id] = rec
    return out


def record_dispatch(aios_dir, effect_id, actor, attempt_id, provider):
    try:
        return _dispatch(aios_dir, effect_id, actor, attempt_id, provider)
    except (ValueError, KeyError, TransitionError) as exc:
        raise ExternalEffectError(str(exc)) from exc


def record_unknown(aios_dir, effect_id, actor, reason):
    try:
        return _unknown(aios_dir, effect_id, actor, reason)
    except (ValueError, KeyError, TransitionError) as exc:
        raise ExternalEffectError(str(exc)) from exc


def record_observation(aios_dir, effect_id, actor, outcome, provider_observation):
    try:
        return _observe(aios_dir, effect_id, actor, outcome, provider_observation)
    except (ValueError, KeyError, TransitionError) as exc:
        raise ExternalEffectError(str(exc)) from exc


__all__ = [
    "ExternalEffectError", "TransitionError", "create_effect", "load_effects",
    "record_dispatch", "record_unknown", "record_observation",
]
