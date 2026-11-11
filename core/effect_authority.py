"""Authoritative external-effect transitions for M6.

This module is the single write boundary for provider-facing effects. An
external effect cannot be created, dispatched, retried, or observed unless the
immutable contract and permit authorize the requested effect. Identity fields
are immutable after creation; attempt IDs are deterministic and tied to the
effect/attempt number; observations must carry AIOS-owned cryptographic
evidence bound to the executing provider and attempt.

UNKNOWN is ambiguous and cannot be retried from caller-supplied authorization.
Retry remains blocked until an independently deployed issuer/verifier is configured.
"""

import hashlib
import json
import os

from .authority import authorize, load_contract, load_permit
from .contract import verify_permit
from .mutation import (TransitionError, _MutationLock, _commit_batch_unlocked,
                      _recover_pending_unlocked, canonical_json)

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
    effect_id = _id(contract_id, logical_operation_id, actor)
    path = _path(aios_dir, effect_id)
    with _MutationLock(aios_dir):
        _recover_pending_unlocked(aios_dir)
        # Authorization reads share the same lock as the create precondition
        # and durable write, preventing a concurrent policy/permit mutation
        # from invalidating the decision between check and commit.
        contract, _permit = _authorized_contract(
            aios_dir, contract_id, permit_id, actor, effect_type
        )
        rec = {
            "record_type": "EXTERNAL_EFFECT", "effect_id": effect_id,
            "contract_id": contract_id, "logical_operation_id": logical_operation_id,
            "actor": actor, "effect_type": effect_type, "permit_id": permit_id,
            "policy_digest": contract["policy_digest"], "max_attempts": contract["max_attempts"],
            "state": "PLANNED", "attempt": 0,
        }
        if os.path.exists(path):
            existing = _load(path)
            if canonical_json(existing) == canonical_json(rec):
                return existing
            raise TransitionError("external effect identity collision with different content")
        event = {"kind": "external_effect", "action": "create", "effect_id": effect_id,
                 "contract_id": contract_id, "permit_id": permit_id, "effect_type": effect_type,
                 "state": "PLANNED", "actor": actor}
        _commit_batch_unlocked(aios_dir, [(os.path.join("effects", effect_id + ".json"), rec),
                                          (os.path.join("events", "effect-create-" + effect_id + ".json"), event)])
    return rec


def _persist_transition(aios_dir, current, target, actor, fields):
    effect_id = current["effect_id"]
    updated = dict(current)
    updated.update(fields)
    updated["state"] = target
    event = {
        "kind": "external_effect", "action": "transition", "effect_id": effect_id,
        "from_state": current["state"], "to_state": target, "actor": actor,
        "attempt": updated.get("attempt", 0),
    }
    _commit_batch_unlocked(aios_dir, [(os.path.join("effects", effect_id + ".json"), updated),
                            (os.path.join("events", "effect-" + effect_id + "-" + target + ".json"), event)],
                 )
    return updated


def transition(aios_dir, effect_id, target, actor, **fields):
    _validate_strings(("effect_id", effect_id), ("actor", actor))
    if target not in STATES:
        raise ValueError("invalid effect state")
    if target in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise TransitionError("terminal outcomes must use observe() with validated provider evidence")
    allowed_fields = {
        "UNKNOWN": {"unknown_reason"},
    }.get(target, set())
    if set(fields) - allowed_fields:
        raise TransitionError("effect transition attempted to mutate protected or unsupported fields")
    if target == "DISPATCHED":
        raise TransitionError("undefined external-effect transition: direct DISPATCHED entry is not allowed")
    path = _path(aios_dir, effect_id)
    with _MutationLock(aios_dir):
        _recover_pending_unlocked(aios_dir)
        if not os.path.exists(path):
            raise KeyError(f"unknown effect: {effect_id}")
        current = _load(path)
        _validate_persisted_effect(aios_dir, current)
        if actor != current.get("actor"):
            raise TransitionError("effect transition actor does not match effect owner")
        if current.get("state") not in _ALLOWED or target not in _ALLOWED[current["state"]]:
            raise TransitionError(f"undefined external-effect transition: {current.get('state')} -> {target}")
        return _persist_transition(aios_dir, current, target, actor, fields)

def _transition_dispatch(aios_dir, current, actor, *, attempt, attempt_id, provider):
    """Dispatch while the caller owns _MutationLock and validated PLANNED state."""
    effect_id = current["effect_id"]
    if current.get("state") != "PLANNED":
        raise TransitionError(f"initial dispatch requires PLANNED effect, got {current.get('state')}")
    updated = dict(current)
    updated.update({"state": "DISPATCHED", "attempt": attempt,
                    "attempt_id": attempt_id, "provider": provider,
                    "execution_claimed": False})
    event = {
        "kind": "external_effect", "action": "dispatch", "effect_id": effect_id,
        "from_state": current["state"], "to_state": "DISPATCHED", "actor": actor,
        "attempt": attempt, "attempt_id": attempt_id, "provider": provider,
    }
    _commit_batch_unlocked(aios_dir, [(os.path.join("effects", effect_id + ".json"), updated),
                            (os.path.join("events", "effect-" + effect_id + "-DISPATCHED-attempt-" + str(attempt) + ".json"), event)],
                 )
    return updated

def dispatch(aios_dir, effect_id, actor, attempt_id, provider):
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    path = _path(aios_dir, effect_id)
    with _MutationLock(aios_dir):
        _recover_pending_unlocked(aios_dir)
        if not os.path.exists(path):
            raise KeyError(f"unknown effect: {effect_id}")
        current = _load(path)
        _validate_persisted_effect(aios_dir, current)
        if actor != current.get("actor"):
            raise TransitionError("dispatch actor does not match effect owner")
        if current.get("state") != "PLANNED":
            raise TransitionError(f"initial dispatch requires PLANNED effect, got {current.get('state')}")
        if attempt_id != _attempt_id(effect_id, 1):
            raise ValueError("attempt_id does not match initial effect attempt")
        if int(current.get("max_attempts", 0)) < 1:
            raise TransitionError("effect has no authorized execution attempts")
        return _transition_dispatch(aios_dir, current, actor,
                                    attempt=1, attempt_id=attempt_id, provider=provider)


def claim_execution(aios_dir, effect_id, actor, attempt_id, provider):
    """Atomically claim the authoritative dispatched attempt exactly once.

    Contract and effect data are loaded from the authority store, not from
    caller dictionaries. A persisted claim is never reusable after a crash:
    ambiguous execution remains blocked rather than replaying a side effect.
    """
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    path = _path(aios_dir, effect_id)
    with _MutationLock(aios_dir):
        _recover_pending_unlocked(aios_dir)
        if not os.path.exists(path):
            raise KeyError(f"unknown effect: {effect_id}")
        current = _load(path)
        contract, _permit = _validate_persisted_effect(aios_dir, current)
        if actor != current.get("actor"):
            raise TransitionError("execution actor does not match effect owner")
        if current.get("state") != "DISPATCHED":
            raise TransitionError("execution claim requires authoritative DISPATCHED effect")
        if attempt_id != current.get("attempt_id") or attempt_id != _attempt_id(effect_id, current.get("attempt")):
            raise TransitionError("execution attempt does not match authoritative dispatched attempt")
        if provider != current.get("provider"):
            raise TransitionError("execution provider does not match authoritative dispatched provider")
        if not any(
            isinstance(ref, str) and ref.split("@", 1)[0] == provider
            for ref in contract.get("capabilities", [])
        ):
            raise PermissionError("provider capability is not authorized by persisted contract")
        if current.get("execution_claimed", False):
            raise TransitionError("dispatched attempt already has a single-use execution claim")
        updated = dict(current)
        updated["execution_claimed"] = True
        updated["execution_claimed_attempt_id"] = attempt_id
        event = {
            "kind": "external_effect", "action": "execution_claim",
            "effect_id": effect_id, "state": "DISPATCHED",
            "actor": actor, "attempt": current.get("attempt"),
            "attempt_id": attempt_id, "provider": provider,
        }
        _commit_batch_unlocked(
            aios_dir,
            [(os.path.join("effects", effect_id + ".json"), updated),
             (os.path.join("events", "effect-" + effect_id + "-EXECUTION_CLAIMED-attempt-" +
                           str(current.get("attempt")) + ".json"), event)],
        )
        return contract, updated


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt, retry_authorization=None):
    """Fail closed: UNKNOWN retry requires an independent issuer, not caller data."""
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    raise TransitionError(
        "UNKNOWN retry BLOCKED: independent issuer verification is not configured"
    )

def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def observe(aios_dir, effect_id, actor, outcome, provider_observation):
    _validate_strings(("effect_id", effect_id), ("actor", actor))
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    path = _path(aios_dir, effect_id)
    with _MutationLock(aios_dir):
        _recover_pending_unlocked(aios_dir)
        if not os.path.exists(path):
            raise KeyError(f"unknown effect: {effect_id}")
        current = _load(path)
        _validate_persisted_effect(aios_dir, current)
        if actor != current.get("actor"):
            raise TransitionError("observation actor does not match effect owner")
        attempt_id = provider_observation.get("attempt_id")
        provider = provider_observation.get("provider")
        evidence = provider_observation.get("evidence")
        if current.get("state") != "DISPATCHED":
            raise TransitionError("observation requires a currently DISPATCHED attempt")
        if attempt_id != current.get("attempt_id"):
            raise TransitionError("observation attempt does not match dispatched attempt")
        if provider != current.get("provider"):
            raise TransitionError("observation provider does not match dispatched provider")
        if evidence.get("provider") != provider:
            raise ValueError("evidence provider does not match effect provider")
        # An unkeyed digest proves payload integrity, not issuer identity or
        # provider origin. No independent trust-root/verifier is configured,
        # so terminal observations remain fail-closed.
        raise PermissionError(
            "observation BLOCKED: independent evidence issuer/verifier is not configured"
        )

