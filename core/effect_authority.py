"""Authoritative external-effect transitions for M6.

This module is the single write boundary for provider-facing effects. Receipt
creation is part of the authoritative observation transition; callers cannot
observe successfully and then separately manufacture a receipt.

Attempt records are immutable snapshots. Retry advances to a new attempt
record; it never rewrites the identity of an earlier attempt.
"""

import hashlib
import json
import os

from .authority import authorize, load_contract, load_permit
from .contract import verify_permit
from .evidence import verify_evidence
from .evaluation import attempt_path, build_receipt_record, receipt_path
from .mutation import TransitionError, canonical_json, commit_batch, recover_pending

STATES = ("PLANNED", "DISPATCHED", "UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE")
_ALLOWED = {
    "PLANNED": {"DISPATCHED"},
    "DISPATCHED": {"UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE"},
    "UNKNOWN": {"DISPATCHED"},
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


def _attempt_record(effect, attempt_id, attempt, actor, provider):
    body = {"record_type": "EXECUTION_ATTEMPT", "attempt_id": attempt_id,
            "effect_id": effect["effect_id"], "attempt": attempt,
            "actor": actor, "provider": provider}
    body["digest"] = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    return body


def _commit_attempt(aios_dir, effect, attempt_id, attempt, actor, provider):
    rec = _attempt_record(effect, attempt_id, attempt, actor, provider)
    path = attempt_path(aios_dir, attempt_id)
    if os.path.exists(path):
        existing = _load(path)
        if canonical_json(existing) == canonical_json(rec):
            return rec
        raise TransitionError("attempt identity collision")
    return rec


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


def transition(aios_dir, effect_id, target, actor, **fields):
    """Apply only non-authoritative state changes.

    Dispatch and observation are separate authority boundaries because they
    create immutable execution-attempt/receipt lineage. Keeping those targets
    out of this generic helper prevents a caller from forging DISPATCHED or
    OBSERVED state by supplying fields directly.
    """
    _validate_strings(("effect_id", effect_id), ("actor", actor))
    if target in ("DISPATCHED", "OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise TransitionError(
            "authoritative execution transition must use dispatch/retry_dispatch/observe"
        )
    if target not in STATES:
        raise ValueError("invalid effect state")
    allowed_fields = {"UNKNOWN": {"unknown_reason"}}.get(target, set())
    if set(fields) - allowed_fields:
        raise TransitionError("effect transition attempted to mutate protected or unsupported fields")
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    current = _load(path)
    _validate_persisted_effect(aios_dir, current)
    if actor != current.get("actor"):
        raise TransitionError("effect transition actor does not match effect owner")
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
    updated = dict(current, state="DISPATCHED", attempt=1, attempt_id=attempt_id, provider=provider)
    event = {"kind": "external_effect", "action": "dispatch", "effect_id": effect_id,
             "from_state": "PLANNED", "to_state": "DISPATCHED", "actor": actor,
             "attempt": 1, "attempt_id": attempt_id, "provider": provider}
    attempt_rec = _commit_attempt(aios_dir, current, attempt_id, 1, actor, provider)
    commit_batch(aios_dir, [
        (os.path.join("effects", effect_id + ".json"), updated),
        (os.path.join("attempts", attempt_id.replace("/", "_") + ".json"), attempt_rec),
        (os.path.join("events", "effect-" + effect_id + "-DISPATCHED-attempt-1.json"), event),
    ])
    return updated


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt):
    """Explicitly dispatch the next attempt for an UNKNOWN effect."""
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    current = _load(path)
    _validate_persisted_effect(aios_dir, current)
    if current.get("actor") != actor:
        raise TransitionError("retry actor does not match effect owner")
    if current.get("state") != "UNKNOWN":
        raise TransitionError(f"retry requires UNKNOWN effect, got {current.get('state')}")
    expected = int(current.get("attempt", 0)) + 1
    if attempt != expected:
        raise TransitionError(f"retry attempt must be {expected}, got {attempt}")
    if attempt > int(current.get("max_attempts", 0)):
        raise TransitionError("retry exceeds contract attempt budget")
    if attempt_id != _attempt_id(effect_id, attempt):
        raise ValueError("attempt_id does not match retry attempt")
    updated = dict(current, state="DISPATCHED", attempt=attempt, attempt_id=attempt_id, provider=provider)
    event = {"kind": "external_effect", "action": "retry_dispatch", "effect_id": effect_id,
             "from_state": "UNKNOWN", "to_state": "DISPATCHED", "actor": actor,
             "attempt": attempt, "attempt_id": attempt_id, "provider": provider}
    attempt_rec = _commit_attempt(aios_dir, current, attempt_id, attempt, actor, provider)
    commit_batch(aios_dir, [
        (os.path.join("effects", effect_id + ".json"), updated),
        (os.path.join("attempts", attempt_id.replace("/", "_") + ".json"), attempt_rec),
        (os.path.join("events", "effect-" + effect_id + "-DISPATCHED-attempt-" + str(attempt) + ".json"), event),
    ])
    return updated


def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def observe(aios_dir, effect_id, actor, outcome, provider_observation):
    """Authoritatively observe an attempt and atomically persist its receipt."""
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
    if current.get("state") != "DISPATCHED":
        raise TransitionError("observation requires a currently DISPATCHED attempt")
    if attempt_id != current.get("attempt_id"):
        raise TransitionError("observation attempt does not match dispatched attempt")
    if provider != current.get("provider"):
        raise TransitionError("observation provider does not match dispatched provider")
    if not isinstance(evidence, dict) or not verify_evidence(evidence):
        raise ValueError("observation requires a valid AIOS evidence record")
    if evidence.get("provider") != provider:
        raise ValueError("evidence provider does not match effect provider")

    receipt = build_receipt_record(current, provider_observation)
    receipt_id = receipt["receipt_id"]
    receipt_file = receipt_path(aios_dir, receipt_id)
    if os.path.exists(receipt_file):
        existing = _load(receipt_file)
        if canonical_json(existing) != canonical_json(receipt):
            raise TransitionError("receipt identity collision")
        raise TransitionError("observation already has an authoritative receipt")

    updated = dict(current, state=outcome, receipt_id=receipt_id, provider_observation=provider_observation)
    event = {"kind": "external_effect", "action": "observe", "effect_id": effect_id,
             "from_state": current["state"], "to_state": outcome, "actor": actor,
             "attempt": current["attempt"], "attempt_id": attempt_id, "provider": provider,
             "receipt_id": receipt_id}
    commit_batch(aios_dir, [
        (os.path.join("effects", effect_id + ".json"), updated),
        (os.path.join("receipts", receipt_id + ".json"), receipt),
        (os.path.join("events", "effect-" + effect_id + "-" + outcome + "-" + receipt_id + ".json"), event),
        (os.path.join("events", "receipt-" + receipt_id + ".json"), {
            "kind": "execution_receipt", "action": "create", "receipt_id": receipt_id,
            "effect_id": effect_id, "attempt_id": attempt_id, "provider": provider,
        }),
    ])
    return updated


__all__ = ["STATES", "create_effect", "transition", "dispatch", "retry_dispatch", "unknown", "observe"]