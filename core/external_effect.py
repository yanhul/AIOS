"""Compatibility facade for the authoritative M6 external-effect boundary.

The repository previously carried two independent effect state machines. That
split made it possible for callers of this legacy API to bypass the stronger
M6 authority/evidence path. Keep the old function names, but delegate every
write to ``core.effect_authority`` so there is one authoritative transition
graph and one evidence contract.
"""

import os

from .effect_authority import create_effect as _create_effect
from .effect_authority import dispatch as _dispatch
from .effect_authority import observe as _observe
from .effect_authority import unknown as _unknown
from .mutation import MutationError, TransitionError


class ExternalEffectError(MutationError):
    pass


def create_effect(aios_dir, contract_id, logical_operation_id, actor):
    return _create_effect(aios_dir, contract_id, logical_operation_id, actor)


def load_effects(aios_dir):
    out = {}
    d = os.path.join(aios_dir, "effects")
    if not os.path.isdir(d):
        return out
    import json
    for fn in os.listdir(d):
        if fn.endswith(".json"):
            with open(os.path.join(d, fn), "r", encoding="utf-8") as fh:
                rec = json.load(fh)
            if rec.get("record_type") == "EXTERNAL_EFFECT":
                out[rec["effect_id"]] = rec
    return out


def record_dispatch(aios_dir, effect_id, attempt_id, provider):
    try:
        return _dispatch(aios_dir, effect_id, "legacy-external-effect", attempt_id, provider)
    except (ValueError, KeyError, TransitionError) as exc:
        raise ExternalEffectError(str(exc)) from exc


def record_unknown(aios_dir, effect_id, reason):
    try:
        return _unknown(aios_dir, effect_id, "legacy-external-effect", reason)
    except (ValueError, KeyError, TransitionError) as exc:
        raise ExternalEffectError(str(exc)) from exc


def record_observation(aios_dir, effect_id, outcome, provider_observation):
    try:
        return _observe(aios_dir, effect_id, "legacy-external-effect", outcome, provider_observation)
    except (ValueError, KeyError, TransitionError) as exc:
        raise ExternalEffectError(str(exc)) from exc


__all__ = [
    "ExternalEffectError", "TransitionError", "create_effect", "load_effects",
    "record_dispatch", "record_unknown", "record_observation",
]
