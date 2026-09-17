"""Compatibility facade for the authoritative M6 external-effect boundary."""

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
    d = os.path.join(aios_dir, "effects")
    if not os.path.isdir(d): return out
    import json
    for fn in os.listdir(d):
        if fn.endswith(".json"):
            with open(os.path.join(d, fn), "r", encoding="utf-8") as fh: rec = json.load(fh)
            if rec.get("record_type") == "EXTERNAL_EFFECT": out[rec["effect_id"]] = rec
    return out


def record_dispatch(aios_dir, effect_id, actor, attempt_id, provider, *, target_sha, evidence_ref, lineage_ref, idempotency_key, attempt_fence):
    try:
        return _dispatch(aios_dir, effect_id, actor, attempt_id, provider, target_sha=target_sha, evidence_ref=evidence_ref, lineage_ref=lineage_ref, idempotency_key=idempotency_key, attempt_fence=attempt_fence)
    except (ValueError, KeyError, TransitionError) as exc:
        raise ExternalEffectError(str(exc)) from exc


def record_unknown(aios_dir, effect_id, actor, reason):
    try: return _unknown(aios_dir, effect_id, actor, reason)
    except (ValueError, KeyError, TransitionError) as exc: raise ExternalEffectError(str(exc)) from exc


def record_observation(aios_dir, effect_id, actor, outcome, provider_observation):
    try: return _observe(aios_dir, effect_id, actor, outcome, provider_observation)
    except (ValueError, KeyError, TransitionError) as exc: raise ExternalEffectError(str(exc)) from exc


__all__ = ["ExternalEffectError", "TransitionError", "create_effect", "load_effects", "record_dispatch", "record_unknown", "record_observation"]
