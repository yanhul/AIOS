"""Authoritative external-effect transitions for M6.

This is the write boundary for provider-facing state. Each transition commits
both the effect record and an audit event in one ``commit_batch``. Provider
success is never inferred: terminal observed states require explicit evidence.

Retry is deliberately a separate semantic operation: callers cannot widen the
generic transition graph by treating UNKNOWN as an ordinary dispatch source.
"""

import hashlib
import json
import os

from .mutation import TransitionError, canonical_json, commit_batch, recover_pending

STATES = ("PLANNED", "DISPATCHED", "UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE")
_ALLOWED = {
    "PLANNED": {"DISPATCHED"},
    "DISPATCHED": {"UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE"},
    "UNKNOWN": {"OBSERVED_SUCCESS", "OBSERVED_FAILURE"},
    "OBSERVED_SUCCESS": set(),
    "OBSERVED_FAILURE": set(),
}


def _id(contract_id, logical_operation_id, actor):
    value = {"contract_id": contract_id, "logical_operation_id": logical_operation_id, "actor": actor}
    return "EF-" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _path(aios_dir, effect_id):
    return os.path.join(aios_dir, "effects", effect_id + ".json")


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _validate_strings(*pairs):
    for name, value in pairs:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")


def create_effect(aios_dir, contract_id, logical_operation_id, actor):
    _validate_strings(("contract_id", contract_id), ("logical_operation_id", logical_operation_id), ("actor", actor))
    recover_pending(aios_dir)
    effect_id = _id(contract_id, logical_operation_id, actor)
    rec = {
        "record_type": "EXTERNAL_EFFECT", "effect_id": effect_id,
        "contract_id": contract_id, "logical_operation_id": logical_operation_id,
        "actor": actor, "state": "PLANNED", "attempt": 0,
    }
    path = _path(aios_dir, effect_id)
    if os.path.exists(path):
        existing = _load(path)
        if canonical_json(existing) == canonical_json(rec):
            return existing
        raise TransitionError("external effect identity collision with different content")
    event = {"kind": "external_effect", "action": "create", "effect_id": effect_id, "state": "PLANNED", "actor": actor}
    commit_batch(aios_dir, [(os.path.join("effects", effect_id + ".json"), rec),
                            (os.path.join("events", "effect-create-" + effect_id + ".json"), event)])
    return rec


def transition(aios_dir, effect_id, target, actor, **fields):
    _validate_strings(("effect_id", effect_id), ("actor", actor))
    if target not in STATES:
        raise ValueError("invalid effect state")
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    current = _load(path)
    if current.get("state") not in _ALLOWED or target not in _ALLOWED[current["state"]]:
        raise TransitionError(f"undefined external-effect transition: {current.get('state')} -> {target}")
    updated = dict(current)
    updated.update(fields)
    updated["state"] = target
    event = {
        "kind": "external_effect", "action": "transition", "effect_id": effect_id,
        "from_state": current["state"], "to_state": target, "actor": actor,
        "attempt": updated.get("attempt", 0),
    }
    commit_batch(aios_dir, [(os.path.join("effects", effect_id + ".json"), updated),
                            (os.path.join("events", "effect-" + effect_id + "-" + target + ".json"), event)])
    return updated


def dispatch(aios_dir, effect_id, actor, attempt_id, provider):
    _validate_strings(("attempt_id", attempt_id), ("provider", provider))
    return transition(aios_dir, effect_id, "DISPATCHED", actor, attempt=1, attempt_id=attempt_id, provider=provider)


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt):
    """Explicitly dispatch the next attempt for an UNKNOWN effect.

    The generic transition graph intentionally does not allow UNKNOWN ->
    DISPATCHED. This narrow entrypoint enforces monotonic attempt sequencing
    and preserves the logical effect identity across retries.
    """
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    current = _load(path)
    if current.get("state") != "UNKNOWN":
        raise TransitionError(f"retry requires UNKNOWN effect, got {current.get('state')}")
    expected = int(current.get("attempt", 0)) + 1
    if attempt != expected:
        raise TransitionError(f"retry attempt must be {expected}, got {attempt}")
    if attempt_id != f"{effect_id}:attempt:{attempt}":
        raise ValueError("attempt_id does not match retry attempt")
    updated = dict(current)
    updated.update({"state": "DISPATCHED", "attempt": attempt,
                    "attempt_id": attempt_id, "provider": provider})
    event = {
        "kind": "external_effect", "action": "retry_dispatch", "effect_id": effect_id,
        "from_state": "UNKNOWN", "to_state": "DISPATCHED", "actor": actor,
        "attempt": attempt, "attempt_id": attempt_id, "provider": provider,
    }
    commit_batch(aios_dir, [(os.path.join("effects", effect_id + ".json"), updated),
                            (os.path.join("events", "effect-" + effect_id + "-DISPATCHED-attempt-" + str(attempt) + ".json"), event)])
    return updated


def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def observe(aios_dir, effect_id, actor, outcome, provider_observation):
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    return transition(aios_dir, effect_id, outcome, actor, provider_observation=provider_observation)
