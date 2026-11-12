"""Compatibility facade for the authoritative M6 external-effect boundary.

Legacy helpers remain available, but they no longer invent a privileged
``legacy-external-effect`` actor. Callers must provide the real contract actor,
permit, and authorized effect type; all writes then flow through the single
M6 authority/evidence state machine.
"""

import os

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
    out = {}
    from .mutation import list_state_names, read_state_json
    for fn in list_state_names(aios_dir, "effects"):
        if fn.endswith(".json"):
            rec = read_state_json(aios_dir, f"effects/{fn}")
            if isinstance(rec, dict) and rec.get("record_type") == "EXTERNAL_EFFECT":
                out[rec["effect_id"]] = rec
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
