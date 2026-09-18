"""Authoritative external-effect transitions for M6.

This module is the single write boundary for provider-facing effects. An
external effect cannot be created, dispatched, retried, or observed unless the
immutable contract and permit authorize the requested effect. Identity fields
are immutable after creation; attempt IDs are deterministic and tied to the
effect/attempt number; observations must carry AIOS-owned cryptographic
evidence bound to the executing provider and attempt.

UNKNOWN is deliberately non-terminal. It can only re-enter DISPATCHED through
the explicit retry path, subject to the contract attempt budget.
"""

import hashlib
import json
import os

from .authority import authorize, load_contract, load_permit
from .contract import verify_permit
from .evidence import verify_evidence
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


def _authorized_contract(aios_dir, contract_id, permit_id, actor, effect_type):
    _validate_strings(("contract_id", contract_id), ("permit_id", permit_id),
                      ("actor", actor), ("effect_type", effect_type))
    authorize(aios_dir, contract_id, permit_id)
    contract = load_contract(aios_dir, contract_id)
    permit = load_permit(aios_dir, permit_id)
    verify_permit(contract, permit)
    if actor != contract["actor"]:
        raise TransitionError("effect actor does not match contract actor")
    if effect_type not in contract["allowed_effects"]:
        raise TransitionError(f"effect type is not authorized by contract: {effect_type}")
    return contract, permit


def _validate_persisted_effect(aios_dir, effect):
    required = ("effect_id", "contract_id", "permit_id", "actor", "effect_type",
                "policy_digest", "max_attempts", "state", "attempt")
    if any(key not in effect for key in required):
        raise TransitionError("persisted effect schema is incomplete")
    contract, permit = _authorized_contract(
        aios_dir, effect["contract_id"], effect["permit_id"],
        effect["actor"], effect["effect_type"])
    if effect["policy_digest"] != contract["policy_digest"]:
        raise TransitionError("effect policy digest differs from authorized contract")
    if effect["max_attempts"] != contract["max_attempts"]:
        raise TransitionError("effect attempt budget differs from authorized contract")
    if not isinstance(effect["attempt"], int) or isinstance(effect["attempt"], bool) or effect["attempt"] < 0:
        raise TransitionError("persisted effect attempt is invalid")
    return contract, permit


def _attempt_id(effect_id, attempt):
    return f"{effect_id}:attempt:{attempt}"


def create_effect(aios_dir, contract_id, logical_operation_id, actor, permit_id, effect_type):
    _validate_strings(("contract_id", contract_id), ("logical_operation_id", logical_operation_id),
                      ("actor", actor), ("permit_id", permit_id), ("effect_type", effect_type))
    contract, _permit = _authorized_contract(aios_dir, contract_id, permit_id, actor, effect_type)
    recover_pending(aios_dir)
    effect_id = _id(contract_id, logical_operation_id, actor)
    rec = {
        "record_type": "EXTERNAL_EFFECT", "effect_id": effect_id,
        "contract_id": contract_id, "logical_operation_id": logical_operation_id,
        "actor": actor, "effect_type": effect_type, "permit_id": permit_id,
        "policy_digest": contract["policy_digest"], "max_attempts": contract["max_attempts"],
        "state": "PLANNED", "attempt": 0,
    }
    path = _path(aios_dir, effect_id)
    if os.path.exists(path):
        existing = _load(path)
        if canonical_json(existing) == canonical_json(rec):
            return existing
        raise TransitionError("external effect identity collision with different content")
    event = {"kind": "external_effect", "action": "create", "effect_id": effect_id,
             "contract_id": contract_id, "permit_id": permit_id, "effect_type": effect_type,
             "state": "PLANNED", "actor": actor}
    commit_batch(aios_dir, [(os.path.join("effects", effect_id + ".json"), rec),
                            (os.path.join("events", "effect-create-" + effect_id + ".json"), event)])
    return rec


def _transition(aios_dir, effect_id, target, actor, *, _retry=False, _event_action="transition", **fields):
    """Single canonical semantic mutation gate for external-effect state."""
    _validate_strings(("effect_id", effect_id), ("actor", actor))
    if target not in STATES:
        raise ValueError("invalid effect state")
    allowed_fields = {
        "DISPATCHED": {"attempt", "attempt_id", "provider"},
        "UNKNOWN": {"unknown_reason"},
        "OBSERVED_SUCCESS": {"provider_observation"},
        "OBSERVED_FAILURE": {"provider_observation"},
    }.get(target, set())
    if set(fields) - allowed_fields:
        raise TransitionError("effect transition attempted to mutate protected or unsupported fields")
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    current = _load(path)
    contract, _permit = _validate_persisted_effect(aios_dir, current)
    if actor != current.get("actor"):
        raise TransitionError("effect transition actor does not match effect owner")

    current_state = current.get("state")
    graph_allows = current_state in _ALLOWED and target in _ALLOWED[current_state]
    if not graph_allows and not (_retry and current_state == "UNKNOWN" and target == "DISPATCHED"):
        raise TransitionError(f"undefined external-effect transition: {current_state} -> {target}")

    if _retry:
        if current_state != "UNKNOWN" or target != "DISPATCHED":
            raise TransitionError("retry transition must be UNKNOWN -> DISPATCHED")
        attempt = fields.get("attempt")
        attempt_id = fields.get("attempt_id")
        provider = fields.get("provider")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
            raise ValueError("retry attempt must be an integer >= 2")
        expected = int(current.get("attempt", 0)) + 1
        if attempt != expected:
            raise TransitionError(f"retry attempt must be {expected}, got {attempt}")
        if attempt > int(current.get("max_attempts", 0)):
            raise TransitionError("retry exceeds contract attempt budget")
        if attempt_id != _attempt_id(effect_id, attempt):
            raise ValueError("attempt_id does not match retry attempt")
        _validate_strings(("provider", provider))
        if not any(
            isinstance(ref, str) and ref.split("@", 1)[0] == provider
            for ref in contract.get("capabilities", [])
        ):
            raise TransitionError("provider capability is not authorized by contract")
        if "external_effect" not in contract.get("allowed_effects", []):
            raise TransitionError("external effect is not authorized by contract")

    updated = dict(current)
    updated.update(fields)
    updated["state"] = target
    event = {
        "kind": "external_effect", "action": _event_action, "effect_id": effect_id,
        "from_state": current["state"], "to_state": target, "actor": actor,
        "attempt": updated.get("attempt", 0),
    }
    event_name = (
        "effect-" + effect_id + "-" + target + ".json"
        if _event_action == "transition"
        else "effect-" + effect_id + "-DISPATCHED-attempt-" + str(updated.get("attempt", 0)) + ".json"
    )
    commit_batch(aios_dir, [
        (os.path.join("effects", effect_id + ".json"), updated),
        (os.path.join("events", event_name), event),
    ])
    return updated


def transition(aios_dir, effect_id, target, actor, **fields):
    """Canonical public transition gate for ordinary effect state changes."""
    return _transition(aios_dir, effect_id, target, actor, **fields)


def dispatch(aios_dir, effect_id, actor, attempt_id, provider):
    _validate_strings(("attempt_id", attempt_id), ("provider", provider))
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    current = _load(path)
    _validate_persisted_effect(aios_dir, current)
    if current.get("state") != "PLANNED":
        raise TransitionError(f"initial dispatch requires PLANNED effect, got {current.get('state')}")
    expected = _attempt_id(effect_id, 1)
    if attempt_id != expected:
        raise ValueError("attempt_id does not match initial effect attempt")
    if int(current.get("max_attempts", 0)) < 1:
        raise TransitionError("effect has no authorized execution attempts")
    return transition(aios_dir, effect_id, "DISPATCHED", actor,
                      attempt=1, attempt_id=attempt_id, provider=provider)


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt):
    """Explicit retry front-door; mutation is delegated to the canonical gate."""
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    return _transition(
        aios_dir, effect_id, "DISPATCHED", actor,
        _retry=True, _event_action="retry_dispatch",
        attempt=attempt, attempt_id=attempt_id, provider=provider,
    )

def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def observe(aios_dir, effect_id, actor, outcome, provider_observation):
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    current = _load(path)
    _validate_persisted_effect(aios_dir, current)
    if actor != current.get("actor"):
        raise TransitionError("observation actor does not match effect owner")
    attempt_id = provider_observation.get("attempt_id")
    provider = provider_observation.get("provider")
    evidence = provider_observation.get("evidence")
    if current.get("state") not in ("DISPATCHED", "UNKNOWN"):
        raise TransitionError("observation requires a currently DISPATCHED or UNKNOWN attempt")
    if attempt_id != current.get("attempt_id"):
        raise TransitionError("observation attempt does not match dispatched attempt")
    if provider != current.get("provider"):
        raise TransitionError("observation provider does not match dispatched provider")
    if not isinstance(evidence, dict) or not verify_evidence(evidence):
        raise ValueError("observation requires a valid AIOS evidence record")
    if evidence.get("provider") != provider:
        raise ValueError("evidence provider does not match effect provider")
    return transition(aios_dir, effect_id, outcome, actor, provider_observation=provider_observation)


__all__ = ["STATES", "create_effect", "transition", "dispatch", "retry_dispatch", "unknown", "observe"]
