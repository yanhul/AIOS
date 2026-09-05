"""Authoritative external-effect transitions for M6.

The effect record is the durable boundary around provider execution. A
DISPATCHING state is committed *before* the provider is called. If the
process dies after that commit and before a provider observation is persisted,
recovery converts DISPATCHING to UNKNOWN. UNKNOWN is never retried blindly:
an explicit provider observation must reconcile it before retry_dispatch is
allowed.
"""

import hashlib
import json
import os

from .mutation import TransitionError, canonical_json, commit_batch, recover_pending

STATES = (
    "PLANNED",
    "DISPATCHING",
    "DISPATCHED",
    "UNKNOWN",
    "OBSERVED_SUCCESS",
    "OBSERVED_FAILURE",
)
_ALLOWED = {
    "PLANNED": {"DISPATCHING"},
    "DISPATCHING": {"DISPATCHED", "UNKNOWN"},
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


def begin_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt=1):
    """Durably journal provider intent immediately before provider execution."""
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise ValueError("attempt must be a positive integer")
    if attempt_id != f"{effect_id}:attempt:{attempt}":
        raise ValueError("attempt_id does not match attempt")
    current = transition(
        aios_dir, effect_id, "DISPATCHING", actor,
        attempt=attempt, attempt_id=attempt_id, provider=provider,
    )
    return current


def mark_dispatched(aios_dir, effect_id, actor):
    """Record that provider dispatch returned without an authoritative outcome."""
    return transition(aios_dir, effect_id, "DISPATCHED", actor)


def dispatch(aios_dir, effect_id, actor, attempt_id, provider):
    """Backward-compatible provider-dispatch entrypoint.

    Callers that can crash between intent journaling and provider execution
    should use ``begin_dispatch`` -> provider call -> ``mark_dispatched``.
    This helper preserves the old API by recording the intent and then the
    dispatched marker as one logical operation; it does not itself call a
    provider.
    """
    begin_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt=1)
    return mark_dispatched(aios_dir, effect_id, actor)


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt):
    """Explicitly dispatch the next attempt for an UNKNOWN effect.

    UNKNOWN -> DISPATCHING is the only retry entrypoint. The caller must then
    execute the provider and explicitly mark the resulting state. This keeps
    retries distinguishable and prevents an agent from widening the generic
    transition graph.
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
    return begin_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt=attempt)


def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def reconcile_dispatch(aios_dir, effect_id, actor, reason="restart or interrupted provider call"):
    """Convert an interrupted DISPATCHING intent to UNKNOWN.

    This is deliberately not an inferred success/failure transition. It only
    establishes that provider visibility is uncertain, forcing explicit
    reconciliation before any retry.
    """
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def reconcile_inflight(aios_dir, actor, reason="restart or interrupted provider call"):
    """Reconcile every durable DISPATCHING intent after process restart."""
    _validate_strings(("actor", actor), ("reason", reason))
    recover_pending(aios_dir)
    effects_dir = os.path.join(aios_dir, "effects")
    if not os.path.isdir(effects_dir):
        return []
    reconciled = []
    for name in sorted(os.listdir(effects_dir)):
        if not name.endswith(".json"):
            continue
        effect_id = name[:-5]
        record = _load(os.path.join(effects_dir, name))
        if record.get("state") == "DISPATCHING":
            reconciled.append(reconcile_dispatch(aios_dir, effect_id, actor, reason))
    return reconciled


def observe(aios_dir, effect_id, actor, outcome, provider_observation):
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    return transition(aios_dir, effect_id, outcome, actor, provider_observation=provider_observation)
