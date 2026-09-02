"""Durable external-effect state machine for AIOS contract execution.

No provider execution is inferred. A successful terminal state requires an
explicit provider observation. UNKNOWN is durable and can only be resolved by
a later explicit observation.
"""

import datetime
import hashlib
import json
import os

from .mutation import MutationError, TransitionError, canonical_json

STATES = ("PLANNED", "DISPATCHED", "UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE")
_ALLOWED = {
    "PLANNED": {"DISPATCHED"},
    "DISPATCHED": {"UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE"},
    "UNKNOWN": {"OBSERVED_SUCCESS", "OBSERVED_FAILURE"},
    "OBSERVED_SUCCESS": set(),
    "OBSERVED_FAILURE": set(),
}
_DIR = "effects"


class ExternalEffectError(MutationError):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _effect_id(contract_id, logical_operation_id, actor):
    logical = {"contract_id": contract_id, "logical_operation_id": logical_operation_id, "actor": actor}
    return "EF-" + hashlib.sha256(canonical_json(logical).encode("utf-8")).hexdigest()


def _path(aios_dir, effect_id):
    return os.path.join(aios_dir, _DIR, effect_id + ".json")


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_effects(aios_dir):
    out = {}
    d = os.path.join(aios_dir, _DIR)
    if not os.path.isdir(d):
        return out
    for fn in os.listdir(d):
        if fn.endswith(".json"):
            rec = _load(os.path.join(d, fn))
            out[rec["effect_id"]] = rec
    return out


def _persist(aios_dir, rec):
    d = os.path.join(aios_dir, _DIR)
    os.makedirs(d, exist_ok=True)
    path = _path(aios_dir, rec["effect_id"])
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, sort_keys=True, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def create_effect(aios_dir, contract_id, logical_operation_id, actor):
    if not all(isinstance(x, str) and x.strip() for x in (contract_id, logical_operation_id, actor)):
        raise ExternalEffectError("contract_id, logical_operation_id and actor are required")
    effect_id = _effect_id(contract_id, logical_operation_id, actor)
    rec = {
        "record_type": "EXTERNAL_EFFECT", "effect_id": effect_id,
        "contract_id": contract_id, "logical_operation_id": logical_operation_id,
        "actor": actor, "state": "PLANNED", "attempt": 0,
        "created_at": _now(), "updated_at": _now(),
    }
    path = _path(aios_dir, effect_id)
    if os.path.exists(path):
        existing = _load(path)
        if canonical_json({k: v for k, v in existing.items() if k not in ("created_at", "updated_at")}) == canonical_json({k: v for k, v in rec.items() if k not in ("created_at", "updated_at")}):
            return existing
        raise TransitionError("external effect identity collision with different content")
    _persist(aios_dir, rec)
    return rec


def _transition(aios_dir, effect_id, target, **fields):
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise ExternalEffectError(f"unknown effect: {effect_id}")
    rec = _load(path)
    current = rec["state"]
    if target not in _ALLOWED[current]:
        raise TransitionError(f"undefined external-effect transition: {current} -> {target}")
    rec.update(fields)
    rec["state"] = target
    rec["updated_at"] = _now()
    _persist(aios_dir, rec)
    return rec


def record_dispatch(aios_dir, effect_id, attempt_id, provider):
    if not all(isinstance(x, str) and x.strip() for x in (attempt_id, provider)):
        raise ExternalEffectError("attempt_id and provider are required")
    return _transition(aios_dir, effect_id, "DISPATCHED", attempt_id=attempt_id, provider=provider, attempt=1)


def record_unknown(aios_dir, effect_id, reason):
    if not isinstance(reason, str) or not reason.strip():
        raise ExternalEffectError("UNKNOWN requires a reason")
    return _transition(aios_dir, effect_id, "UNKNOWN", unknown_reason=reason)


def record_observation(aios_dir, effect_id, outcome, provider_observation):
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ExternalEffectError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ExternalEffectError("provider_observation must be a non-empty dict")
    return _transition(aios_dir, effect_id, outcome, provider_observation=provider_observation)
