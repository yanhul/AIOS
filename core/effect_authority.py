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


def _effect_rel(effect_id):
    return os.path.join("effects", effect_id + ".json")


def _expect_unchanged(rel_path, snapshot):
    """Build a CAS precondition: ``rel_path`` must still equal ``snapshot``.

    ``snapshot`` of ``None`` means the file must not exist yet. Evaluated
    under the mutation lock by ``commit_batch``.
    """
    expected = None if snapshot is None else canonical_json(snapshot)

    def _check(aios_dir):
        path = os.path.join(aios_dir, rel_path)
        if not os.path.exists(path):
            actual = None
        else:
            try:
                actual = canonical_json(_load(path))
            except (OSError, ValueError) as exc:
                raise TransitionError(f"concurrent modification: unreadable {rel_path}: {exc}") from exc
        if actual != expected:
            raise TransitionError(f"concurrent modification detected for {rel_path}; transition aborted")
    return _check


def _all_of(*checks):
    def _check(aios_dir):
        for check in checks:
            check(aios_dir)
    return _check


def _require_provider_authorized(contract, provider):
    refs = contract.get("capabilities", [])
    if not any(isinstance(ref, str) and ref.split("@", 1)[0] == provider for ref in refs):
        raise TransitionError(f"provider is not authorized by contract capabilities: {provider}")


def _load_owned_effect(aios_dir, effect_id, actor, label):
    _validate_strings(("effect_id", effect_id), ("actor", actor))
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    current = _load(path)
    contract, permit = _validate_persisted_effect(aios_dir, current)
    if current.get("effect_id") != effect_id:
        raise TransitionError("persisted effect identity does not match requested effect")
    if actor != current.get("actor"):
        raise TransitionError(f"{label} actor does not match effect owner")
    if permit.get("actor") not in (None, actor):
        raise TransitionError(f"{label} actor does not match permit actor")
    return current, contract


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
    try:
        commit_batch(aios_dir, [(_effect_rel(effect_id), rec),
                                (os.path.join("events", "effect-create-" + effect_id + ".json"), event)],
                     precondition=_expect_unchanged(_effect_rel(effect_id), None))
    except TransitionError:
        # Lost a create race: idempotent only if the winner wrote identical content.
        existing = _load(path)
        if canonical_json(existing) == canonical_json(rec):
            return existing
        raise TransitionError("external effect identity collision with different content")
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
    current, _contract = _load_owned_effect(aios_dir, effect_id, actor, "effect transition")
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
    commit_batch(aios_dir, [(_effect_rel(effect_id), updated),
                            (os.path.join("events", "effect-" + effect_id + "-" + target + ".json"), event)],
                 precondition=_expect_unchanged(_effect_rel(effect_id), current))
    return updated


def _transition_dispatch(aios_dir, current, actor, *, attempt, attempt_id, provider,
                         extra_payloads=(), extra_checks=()):
    """Dispatch mutation. ``current`` is the validated snapshot; the commit is a
    CAS against it so a concurrent writer cannot be silently overwritten."""
    effect_id = current["effect_id"]
    updated = dict(current)
    updated.update({"state": "DISPATCHED", "attempt": attempt,
                    "attempt_id": attempt_id, "provider": provider})
    event = {
        "kind": "external_effect", "action": "dispatch", "effect_id": effect_id,
        "from_state": current["state"], "to_state": "DISPATCHED", "actor": actor,
        "attempt": attempt, "attempt_id": attempt_id, "provider": provider,
    }
    payloads = [(_effect_rel(effect_id), updated),
                (os.path.join("events", "effect-" + effect_id + "-DISPATCHED-attempt-" + str(attempt) + ".json"), event)]
    payloads.extend(extra_payloads)
    commit_batch(aios_dir, payloads,
                 precondition=_all_of(_expect_unchanged(_effect_rel(effect_id), current), *extra_checks))
    return updated


def dispatch(aios_dir, effect_id, actor, attempt_id, provider):
    _validate_strings(("attempt_id", attempt_id), ("provider", provider))
    current, contract = _load_owned_effect(aios_dir, effect_id, actor, "dispatch")
    _require_provider_authorized(contract, provider)
    if current.get("state") != "PLANNED":
        raise TransitionError(f"initial dispatch requires PLANNED effect, got {current.get('state')}")
    expected = _attempt_id(effect_id, 1)
    if attempt_id != expected:
        raise ValueError("attempt_id does not match initial effect attempt")
    if int(current.get("max_attempts", 0)) < 1:
        raise TransitionError("effect has no authorized execution attempts")
    return _transition_dispatch(aios_dir, current, actor,
                                attempt=1, attempt_id=attempt_id, provider=provider)


# --- Retry authority -------------------------------------------------------

RETRY_AUTH_DIR = "retry_authorizations"
_RETRY_AUTH_FIELDS = ("authorization_id", "effect_id", "contract_id", "permit_id", "actor",
                      "attempt", "issuer", "reason", "unknown_reason", "mode")


def _retry_auth_rel(authorization_id):
    return os.path.join(RETRY_AUTH_DIR, authorization_id + ".json")


def _retry_auth_digest(record):
    body = {key: record.get(key) for key in _RETRY_AUTH_FIELDS}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def issue_retry_authorization(aios_dir, effect_id, actor, attempt, issuer, reason):
    """Persist an AIOS-issued, single-use authorization to retry an UNKNOWN effect.

    The issuer must be a party other than the executing actor (separation of
    duties): an executor cannot authorize its own retry of an ambiguous effect.
    """
    _validate_strings(("issuer", issuer), ("reason", reason))
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    if issuer == actor:
        raise TransitionError("retry authorization issuer must differ from the executing actor")
    current, _contract = _load_owned_effect(aios_dir, effect_id, actor, "retry authorization")
    if current.get("state") != "UNKNOWN":
        raise TransitionError(f"retry authorization requires UNKNOWN effect, got {current.get('state')}")
    if attempt != int(current["attempt"]) + 1:
        raise TransitionError(f"retry authorization attempt must be {int(current['attempt']) + 1}, got {attempt}")
    if attempt > int(current["max_attempts"]):
        raise TransitionError("retry authorization exceeds contract attempt budget")
    authorization_id = "RA-" + hashlib.sha256(
        canonical_json({"effect_id": effect_id, "attempt": attempt}).encode("utf-8")).hexdigest()
    rec = {
        "record_type": "RETRY_AUTHORIZATION", "authorization_id": authorization_id,
        "effect_id": effect_id, "contract_id": current["contract_id"], "permit_id": current["permit_id"],
        "actor": actor, "attempt": attempt, "issuer": issuer, "reason": reason,
        "unknown_reason": current.get("unknown_reason"), "mode": "EXPLICIT",
    }
    rec["digest"] = _retry_auth_digest(rec)
    rec["status"] = "ISSUED"
    rel = _retry_auth_rel(authorization_id)
    existing_path = os.path.join(aios_dir, rel)
    if os.path.exists(existing_path):
        existing = _load(existing_path)
        if existing.get("status") == "ISSUED" and existing.get("digest") == rec["digest"]:
            return existing
        raise TransitionError("retry authorization already exists for this attempt (consumed or conflicting)")
    event = {"kind": "external_effect", "action": "retry_authorized", "effect_id": effect_id,
             "authorization_id": authorization_id, "attempt": attempt, "issuer": issuer, "actor": actor}
    commit_batch(aios_dir, [(rel, rec),
                            (os.path.join("events", "effect-" + effect_id + "-RETRY-AUTH-attempt-" + str(attempt) + ".json"), event)],
                 precondition=_all_of(_expect_unchanged(_effect_rel(effect_id), current),
                                      _expect_unchanged(rel, None)))
    return rec


def _verify_retry_authorization(aios_dir, supplied, current, actor, attempt):
    if isinstance(supplied, str):
        authorization_id = supplied
    elif isinstance(supplied, dict):
        authorization_id = supplied.get("authorization_id")
    else:
        authorization_id = None
    if not isinstance(authorization_id, str) or not authorization_id.startswith("RA-"):
        raise TransitionError("UNKNOWN retry requires an AIOS-issued retry authorization")
    rel = _retry_auth_rel(authorization_id)
    path = os.path.join(aios_dir, rel)
    if not os.path.exists(path):
        raise TransitionError("retry authorization was not issued by AIOS")
    record = _load(path)
    if record.get("record_type") != "RETRY_AUTHORIZATION" or record.get("digest") != _retry_auth_digest(record):
        raise TransitionError("retry authorization record failed integrity check")
    if record.get("status") != "ISSUED":
        raise TransitionError("retry authorization already consumed or revoked")
    for key, value in (("effect_id", current["effect_id"]), ("contract_id", current["contract_id"]),
                       ("permit_id", current["permit_id"]), ("actor", actor), ("attempt", attempt)):
        if record.get(key) != value:
            raise TransitionError(f"retry authorization {key} binding mismatch")
    if isinstance(supplied, dict):
        for key in _RETRY_AUTH_FIELDS:
            if key in supplied and supplied[key] != record.get(key):
                raise TransitionError(f"supplied retry authorization differs from issued record: {key}")
    return rel, record


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt, retry_authorization=None):
    """Explicitly dispatch the next attempt for an UNKNOWN effect.

    Consumes the AIOS-issued retry authorization atomically with the dispatch.
    """
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    current, contract = _load_owned_effect(aios_dir, effect_id, actor, "retry")
    _require_provider_authorized(contract, provider)
    if current.get("state") != "UNKNOWN":
        raise TransitionError(f"retry requires UNKNOWN effect, got {current.get('state')}")
    expected = int(current.get("attempt", 0)) + 1
    if attempt != expected:
        raise TransitionError(f"retry attempt must be {expected}, got {attempt}")
    if attempt > int(current.get("max_attempts", 0)):
        raise TransitionError("retry exceeds contract attempt budget")
    if attempt_id != _attempt_id(effect_id, attempt):
        raise ValueError("attempt_id does not match retry attempt")
    auth_rel, auth = _verify_retry_authorization(aios_dir, retry_authorization, current, actor, attempt)
    consumed = dict(auth)
    consumed.update({"status": "CONSUMED", "consumed_by_attempt_id": attempt_id, "consumed_provider": provider})
    return _transition_dispatch(aios_dir, current, actor,
                                attempt=attempt, attempt_id=attempt_id, provider=provider,
                                extra_payloads=[(auth_rel, consumed)],
                                extra_checks=[_expect_unchanged(auth_rel, auth)])


def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def observation_digest(observation):
    """Digest AIOS binds into the evidence envelope for a raw provider observation."""
    return hashlib.sha256(json.dumps(observation, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("utf-8")).hexdigest()


def observe(aios_dir, effect_id, actor, outcome, provider_observation):
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    current, _contract = _load_owned_effect(aios_dir, effect_id, actor, "observation")
    attempt_id = provider_observation.get("attempt_id")
    provider = provider_observation.get("provider")
    evidence = provider_observation.get("evidence")
    if current.get("state") != "DISPATCHED":
        raise TransitionError("observation requires a currently DISPATCHED attempt")
    if attempt_id != current.get("attempt_id"):
        raise TransitionError("observation attempt does not match dispatched attempt")
    if provider != current.get("provider"):
        raise TransitionError("observation provider does not match dispatched provider")
    if "effect_id" in provider_observation and provider_observation["effect_id"] != effect_id:
        raise TransitionError("observation effect does not match effect")
    if not isinstance(evidence, dict) or not verify_evidence(evidence):
        raise ValueError("observation requires a valid AIOS evidence record")
    if evidence.get("provider") != provider:
        raise ValueError("evidence provider does not match effect provider")
    # Bind evidence to THIS attempt: a digest-valid record from an earlier run
    # (or another effect) must not be replayable into a new attempt.
    if evidence.get("run_id") != current.get("attempt_id"):
        raise ValueError("evidence run_id is not bound to the current attempt")
    raw = provider_observation.get("observation")
    if raw is not None and evidence.get("artifact_ref") != observation_digest(raw):
        raise ValueError("evidence artifact_ref is not bound to the provider observation")
    return transition(aios_dir, effect_id, outcome, actor, provider_observation=provider_observation)


__all__ = ["STATES", "create_effect", "transition", "dispatch", "retry_dispatch", "unknown", "observe",
           "issue_retry_authorization", "observation_digest", "RETRY_AUTH_DIR"]
