"""Authoritative external-effect transitions for M6.

This module is the single write boundary for provider-facing effects. An
external effect cannot be created, dispatched, retried, or observed unless the
immutable contract and permit authorize the requested effect. Identity fields
are immutable after creation; attempt IDs are deterministic and tied to the
effect/attempt number; observations must carry AIOS-owned cryptographic
evidence bound to the executing provider and attempt.

UNKNOWN is deliberately non-terminal. It can leave UNKNOWN only through
AIOS reconciliation: a provider-evidenced APPLIED verdict records the
observation (no retry), NOT_APPLIED is the *only* thing that unlocks the
explicit retry path (with a new attempt identity, within the contract attempt
budget), and INCONCLUSIVE keeps the effect blocked. Caller-supplied retry
authorization dictionaries are never sufficient on their own.

Every accepted observation persists an immutable provider receipt whose
``receipt_id`` is derived from, and bound to, the exact effect_id and
attempt_id. Missing receipts never become success.
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


def transition(aios_dir, effect_id, target, actor, **fields):
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
    if target == "DISPATCHED":
        raise TransitionError("undefined external-effect transition: direct DISPATCHED entry is not allowed")
    if target in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        # Observed outcomes require verified evidence and a persisted receipt;
        # the generic transition path performs neither check.
        raise TransitionError("observed outcomes must be recorded through observe() or reconciliation")
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


def _transition_dispatch(aios_dir, effect_id, actor, *, attempt, attempt_id, provider):
    """Internal dispatch mutation after authority checks."""
    path = _path(aios_dir, effect_id)
    current = _load(path)
    updated = dict(current)
    updated.update({"state": "DISPATCHED", "attempt": attempt,
                    "attempt_id": attempt_id, "provider": provider})
    event = {
        "kind": "external_effect", "action": "dispatch", "effect_id": effect_id,
        "from_state": current["state"], "to_state": "DISPATCHED", "actor": actor,
        "attempt": attempt, "attempt_id": attempt_id, "provider": provider,
    }
    commit_batch(aios_dir, [(os.path.join("effects", effect_id + ".json"), updated),
                            (os.path.join("events", "effect-" + effect_id + "-DISPATCHED-attempt-" + str(attempt) + ".json"), event)])
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
    return _transition_dispatch(aios_dir, effect_id, actor,
                                attempt=1, attempt_id=attempt_id, provider=provider)


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt, retry_authorization=None):
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
    if not isinstance(retry_authorization, dict) or retry_authorization.get("mode") != "EXPLICIT":
        raise TransitionError("UNKNOWN retry requires explicit retry authorization")
    if retry_authorization.get("effect_id") != effect_id:
        raise TransitionError("retry authorization effect binding mismatch")
    if retry_authorization.get("attempt") != attempt:
        raise TransitionError("retry authorization attempt mismatch")
    # The caller-supplied authorization is necessary but never sufficient: AIOS
    # must hold a persisted, provider-evidenced NOT_APPLIED reconciliation for
    # the exact UNKNOWN attempt being replaced.
    previous = int(current.get("attempt", 0))
    rec = load_reconciliation(aios_dir, effect_id, previous)
    if not isinstance(rec, dict) or rec.get("verdict") != "NOT_APPLIED":
        raise TransitionError("UNKNOWN retry requires a persisted NOT_APPLIED reconciliation")
    if rec.get("attempt_id") != current.get("attempt_id") or rec.get("effect_id") != effect_id:
        raise TransitionError("reconciliation is not bound to the UNKNOWN attempt")
    if not isinstance(rec.get("evidence"), dict) or not verify_evidence(rec["evidence"]):
        raise TransitionError("reconciliation evidence is invalid")
    contract, _permit = _validate_persisted_effect(aios_dir, current)
    return _transition_dispatch(aios_dir, effect_id, actor,
                                attempt=attempt, attempt_id=attempt_id, provider=provider)


def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def _receipt_relpath(receipt_id):
    return os.path.join("receipts", receipt_id + ".json")


def _reconciliation_relpath(effect_id, attempt):
    return os.path.join("reconciliations", f"{effect_id}-attempt-{attempt}.json")


def receipt_id_for(effect_id, attempt_id, provider, provider_operation_id, outcome, evidence_digest):
    """Deterministic receipt identity bound to the exact effect and attempt."""
    value = {"effect_id": effect_id, "attempt_id": attempt_id, "provider": provider,
             "provider_operation_id": provider_operation_id, "outcome": outcome,
             "evidence_digest": evidence_digest}
    return "RC-" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _load_current(aios_dir, effect_id):
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    current = _load(path)
    _validate_persisted_effect(aios_dir, current)
    return current


def _validated_observation(current, outcome, provider_observation):
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    attempt_id = provider_observation.get("attempt_id")
    provider = provider_observation.get("provider")
    evidence = provider_observation.get("evidence")
    if attempt_id != current.get("attempt_id"):
        raise TransitionError("observation attempt does not match dispatched attempt")
    if provider != current.get("provider"):
        raise TransitionError("observation provider does not match dispatched provider")
    if "effect_id" in provider_observation and provider_observation["effect_id"] != current["effect_id"]:
        raise TransitionError("observation effect does not match effect")
    if not isinstance(evidence, dict) or not verify_evidence(evidence):
        raise ValueError("observation requires a valid AIOS evidence record")
    if evidence.get("provider") != provider:
        raise ValueError("evidence provider does not match effect provider")
    op_id = provider_observation.get("provider_operation_id")
    if op_id is not None and (not isinstance(op_id, str) or not op_id.strip()):
        raise ValueError("provider_operation_id must be a non-empty string when present")
    return attempt_id, provider, evidence, op_id


def _commit_observation(aios_dir, current, actor, outcome, provider_observation, via, extra=()):
    attempt_id, provider, evidence, op_id = _validated_observation(current, outcome, provider_observation)
    effect_id = current["effect_id"]
    rid = receipt_id_for(effect_id, attempt_id, provider, op_id, outcome, evidence["digest"])
    receipt = {
        "record_type": "PROVIDER_RECEIPT", "receipt_id": rid, "effect_id": effect_id,
        "attempt_id": attempt_id, "attempt": current["attempt"], "contract_id": current["contract_id"],
        "provider": provider, "provider_operation_id": op_id, "outcome": outcome,
        "evidence": evidence, "recorded_via": via,
    }
    receipt_path = os.path.join(aios_dir, _receipt_relpath(rid))
    if os.path.exists(receipt_path):
        raise TransitionError("provider receipt already recorded; duplicate observation rejected")
    updated = dict(current)
    updated.update({"state": outcome, "provider_observation": provider_observation, "receipt_id": rid})
    event = {
        "kind": "external_effect", "action": "observe", "effect_id": effect_id,
        "from_state": current["state"], "to_state": outcome, "actor": actor,
        "attempt": current["attempt"], "attempt_id": attempt_id, "receipt_id": rid, "via": via,
    }
    commit_batch(aios_dir, [
        *extra,
        (_receipt_relpath(rid), receipt),
        (os.path.join("effects", effect_id + ".json"), updated),
        (os.path.join("events", "effect-" + effect_id + "-" + outcome + ".json"), event),
    ])
    return updated


def observe(aios_dir, effect_id, actor, outcome, provider_observation):
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    current = _load_current(aios_dir, effect_id)
    if actor != current.get("actor"):
        raise TransitionError("observation actor does not match effect owner")
    if current.get("state") != "DISPATCHED":
        raise TransitionError("observation requires a currently DISPATCHED attempt")
    return _commit_observation(aios_dir, current, actor, outcome, provider_observation, "observe")


def load_receipt(aios_dir, receipt_id):
    """Load a persisted receipt and verify it is still bound to its effect."""
    _validate_strings(("receipt_id", receipt_id))
    path = os.path.join(aios_dir, _receipt_relpath(receipt_id))
    if not os.path.exists(path):
        raise KeyError(f"unknown receipt: {receipt_id}")
    receipt = _load(path)
    evidence = receipt.get("evidence")
    if not isinstance(evidence, dict) or not verify_evidence(evidence):
        raise TransitionError("persisted receipt evidence is invalid")
    expected = receipt_id_for(receipt.get("effect_id"), receipt.get("attempt_id"), receipt.get("provider"),
                              receipt.get("provider_operation_id"), receipt.get("outcome"), evidence["digest"])
    if expected != receipt_id or receipt.get("receipt_id") != receipt_id:
        raise TransitionError("persisted receipt identity does not match its content")
    effect = _load(_path(aios_dir, receipt["effect_id"]))
    if effect.get("receipt_id") != receipt_id or effect.get("attempt_id") != receipt["attempt_id"]:
        raise TransitionError("persisted receipt is not the receipt of record for its effect")
    if effect.get("state") != receipt["outcome"]:
        raise TransitionError("persisted receipt outcome differs from effect state")
    return receipt


def recover_interrupted(aios_dir, effect_id, actor, reason="interrupted before receipt persistence"):
    """Fail a DISPATCHED effect with no receipt into UNKNOWN after a crash.

    AIOS cannot distinguish "crashed before the provider call" from "provider
    applied the effect, then the process died" without asking the provider,
    so both become UNKNOWN and must be reconciled before any retry.
    """
    current = _load_current(aios_dir, effect_id)
    if current.get("state") != "DISPATCHED":
        raise TransitionError(f"interrupted recovery requires DISPATCHED effect, got {current.get('state')}")
    if current.get("receipt_id"):
        raise TransitionError("dispatched effect already carries a receipt")
    return unknown(aios_dir, effect_id, actor, reason)


RECONCILIATION_VERDICTS = ("APPLIED", "NOT_APPLIED", "INCONCLUSIVE")


def load_reconciliation(aios_dir, effect_id, attempt):
    path = os.path.join(aios_dir, _reconciliation_relpath(effect_id, attempt))
    if not os.path.exists(path):
        return None
    return _load(path)


def reconcile_effect(aios_dir, effect_id, actor, verdict, provider_evidence, *,
                     outcome=None, provider_observation=None):
    """Record an AIOS reconciliation verdict for the current UNKNOWN attempt.

    * APPLIED: requires ``outcome`` and a full ``provider_observation``; the
      effect leaves UNKNOWN with a persisted receipt. It is never retried.
    * NOT_APPLIED: requires provider evidence bound to the exact attempt; this
      record is the only artefact that unlocks ``retry_dispatch``.
    * INCONCLUSIVE: recorded as negative evidence; the effect stays UNKNOWN
      and retry stays blocked.
    """
    if verdict not in RECONCILIATION_VERDICTS:
        raise ValueError("invalid reconciliation verdict")
    current = _load_current(aios_dir, effect_id)
    if actor != current.get("actor"):
        raise TransitionError("reconciliation actor does not match effect owner")
    if current.get("state") != "UNKNOWN":
        raise TransitionError(f"reconciliation requires UNKNOWN effect, got {current.get('state')}")
    attempt = current["attempt"]
    attempt_id = current.get("attempt_id")
    provider = current.get("provider")
    if not isinstance(provider_evidence, dict) or not verify_evidence(provider_evidence):
        raise ValueError("reconciliation requires a valid AIOS evidence record")
    if provider_evidence.get("provider") != provider:
        raise ValueError("reconciliation evidence provider does not match effect provider")
    if provider_evidence.get("run_id") != attempt_id:
        raise ValueError("reconciliation evidence is not bound to the UNKNOWN attempt")
    existing = load_reconciliation(aios_dir, effect_id, attempt)
    if existing is not None and existing.get("verdict") in ("APPLIED", "NOT_APPLIED"):
        raise TransitionError("attempt already has a decisive reconciliation verdict")
    record = {
        "record_type": "EFFECT_RECONCILIATION", "effect_id": effect_id, "attempt": attempt,
        "attempt_id": attempt_id, "provider": provider, "verdict": verdict,
        "evidence": provider_evidence, "actor": actor,
        "supersedes": existing.get("evidence", {}).get("digest") if existing else None,
    }
    rel = _reconciliation_relpath(effect_id, attempt)
    if verdict == "APPLIED":
        if outcome is None or provider_observation is None:
            raise ValueError("APPLIED reconciliation requires outcome and provider_observation")
        return _commit_observation(aios_dir, current, actor, outcome, provider_observation,
                                   "reconciliation", extra=[(rel, record)])
    if outcome is not None or provider_observation is not None:
        raise ValueError("only APPLIED reconciliation may carry an observation")
    event = {"kind": "external_effect", "action": "reconcile", "effect_id": effect_id,
             "attempt": attempt, "attempt_id": attempt_id, "verdict": verdict, "actor": actor}
    commit_batch(aios_dir, [(rel, record),
                            (os.path.join("events", f"effect-{effect_id}-reconcile-{attempt}-{verdict}.json"), event)])
    return record


__all__ = ["STATES", "RECONCILIATION_VERDICTS", "create_effect", "transition", "dispatch", "retry_dispatch",
           "unknown", "observe", "receipt_id_for", "load_receipt", "recover_interrupted",
           "reconcile_effect", "load_reconciliation"]
