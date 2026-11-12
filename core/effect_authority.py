"""Authoritative external-effect transitions for M6.

This module is the single write boundary for provider-facing effects. An
external effect cannot be created, dispatched, retried, or observed unless the
immutable contract and permit authorize the requested effect. Identity fields
are immutable after creation; attempt IDs are deterministic and tied to the
effect/attempt number. Terminal OBSERVED_* states are reachable only through
``observe()``, which mints the AIOS evidence envelope itself (SHA-256 content
binding of the exact raw observation to the current attempt; this is integrity
binding, not issuer authenticity).

UNKNOWN is deliberately non-terminal. It can only re-enter DISPATCHED through
the explicit retry path, subject to the contract attempt budget and a retry
authorization signed by a deployment-registered issuer (see RetryIssuerKeyring).
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Mapping

from .authority import authorize, load_contract, load_permit
from .contract import verify_permit
from .evidence import EvidenceRecord, verify_evidence
from .mutation import TransitionError, canonical_json, commit_batch, recover_pending

STATES = ("PLANNED", "DISPATCHED", "UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE")
_ALLOWED = {
    "PLANNED": {"DISPATCHED"},
    "DISPATCHED": {"UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE"},
    "UNKNOWN": {"OBSERVED_SUCCESS", "OBSERVED_FAILURE"},
    "OBSERVED_SUCCESS": set(),
    "OBSERVED_FAILURE": set(),
}
_OBSERVED = frozenset({"OBSERVED_SUCCESS", "OBSERVED_FAILURE"})


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
    if target in _OBSERVED:
        raise TransitionError("observation outcomes can only be recorded through observe(); "
                              f"direct {target} transition is not allowed")
    current, _contract = _load_owned_effect(aios_dir, effect_id, actor, "effect transition")
    return _commit_transition(aios_dir, current, actor, target, fields)


def _commit_transition(aios_dir, current, actor, target, fields):
    effect_id = current["effect_id"]
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
                         extra_fields=None, extra_payloads=(), extra_checks=()):
    """Dispatch mutation. ``current`` is the validated snapshot; the commit is a
    CAS against it so a concurrent writer cannot be silently overwritten."""
    effect_id = current["effect_id"]
    updated = dict(current)
    updated.update({"state": "DISPATCHED", "attempt": attempt,
                    "attempt_id": attempt_id, "provider": provider})
    if extra_fields:
        updated.update(extra_fields)
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
#
# Trust model (audit F-03). Files under ``aios_dir`` are NOT a trust anchor for
# retry approval: anything an agent can write there it could also forge. Retry
# issuers are registered in a deployment-supplied ``RetryIssuerKeyring``
# (explicit ``keyring=`` argument, or the ``AIOS_RETRY_ISSUER_KEYRING`` JSON
# environment variable), which is never persisted in AIOS state. This reuses
# the existing deployment-secret/HMAC authority model of ``core.attestation``.
# An authorization is an HMAC-SHA256 signature by the issuer's registered
# secret over the complete retry context, including the digest of the exact
# UNKNOWN effect record it approves, so it can only ever match one state.
#
# Limitation (by design of the existing model): HMAC is symmetric. It
# authenticates the issuer against principals that do not hold the issuer's
# secret (e.g. the executing agent), not against the deployment itself.

RETRY_AUTH_DIR = "retry_authorizations"
RETRY_APPROVE_SCOPE = "effect.retry.approve"
DEFAULT_RETRY_AUTH_TTL_SECONDS = 900
MAX_RETRY_AUTH_TTL_SECONDS = 86400
_CLOCK_SKEW_SECONDS = 60
_RETRY_AUTH_ID = re.compile(r"RA-[0-9a-f]{32}")
_RETRY_SIGNED_FIELDS = (
    "record_type", "authorization_id", "effect_id", "contract_id", "permit_id", "actor",
    "issuer", "scope", "effect_state_digest", "previous_attempt", "previous_attempt_id",
    "attempt", "attempt_id", "reason", "unknown_reason", "issued_at", "expires_at",
    "mode", "algorithm",
)
_CONSUMPTION_FIELDS = (
    "record_type", "authorization_id", "authorization_signature", "effect_id",
    "consumed_by_attempt_id", "consumed_provider", "consumed_from_state_digest",
)


class _HmacKeyring:
    """Deployment-supplied HMAC trust anchor. Never persisted in AIOS state."""

    ENV_VAR = None
    LABEL = "principal"

    def __init__(self, issuers):
        label = self.LABEL
        if not isinstance(issuers, Mapping) or not issuers:
            raise ValueError(f"{label} keyring must be a non-empty mapping")
        parsed = {}
        for issuer, entry in issuers.items():
            _validate_strings((label, issuer))
            if not isinstance(entry, Mapping):
                raise ValueError(f"{label} entry must be a mapping: {issuer}")
            secret = entry.get("secret")
            if not isinstance(secret, str) or len(secret) < 16:
                raise ValueError(f"{label} secret must be a string of at least 16 characters: {issuer}")
            scopes = entry.get("scopes", ())
            if not isinstance(scopes, (list, tuple)) or not all(isinstance(x, str) for x in scopes):
                raise ValueError(f"{label} scopes must be a list of strings: {issuer}")
            revoked = entry.get("revoked", False)
            if not isinstance(revoked, bool):
                raise ValueError(f"{label} revoked flag must be boolean: {issuer}")
            parsed[issuer] = {"secret": secret.encode("utf-8"), "scopes": frozenset(scopes), "revoked": revoked}
        self._issuers = parsed

    @classmethod
    def from_env(cls, environ=None):
        raw = (os.environ if environ is None else environ).get(cls.ENV_VAR)
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise TransitionError(f"{cls.LABEL} keyring environment is not valid JSON") from exc
        try:
            return cls(data)
        except ValueError as exc:
            raise TransitionError(f"{cls.LABEL} keyring environment is invalid: {exc}") from exc

    def secret_for(self, issuer, scope):
        label = self.LABEL
        entry = self._issuers.get(issuer) if isinstance(issuer, str) else None
        if entry is None:
            raise TransitionError(f"{label} is not registered in the trusted keyring: {issuer!r}")
        if entry["revoked"]:
            raise TransitionError(f"{label} has been revoked: {issuer}")
        if scope not in entry["scopes"]:
            raise TransitionError(f"{label} is not authorized for {scope}: {issuer}")
        return entry["secret"]

    def __repr__(self):  # never leak secrets into logs/evidence
        return f"{type(self).__name__}(principals={sorted(self._issuers)})"


class RetryIssuerKeyring(_HmacKeyring):
    """Trusted retry issuers (scope ``effect.retry.approve``)."""

    ENV_VAR = "AIOS_RETRY_ISSUER_KEYRING"
    LABEL = "retry issuer"


RETRY_KEYRING_ENV = RetryIssuerKeyring.ENV_VAR
PROVIDER_KEYRING_ENV = "AIOS_PROVIDER_KEYRING"


def _resolve_keyring(keyring):
    if keyring is None:
        keyring = RetryIssuerKeyring.from_env()
    if not isinstance(keyring, RetryIssuerKeyring):
        raise TransitionError("retry authorization requires a deployment-supplied trusted issuer keyring")
    return keyring


def _now(now):
    value = time.time() if now is None else now
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("now must be a number")
    return float(value)


def _effect_state_digest(effect):
    return hashlib.sha256(canonical_json(effect).encode("utf-8")).hexdigest()


def _retry_auth_rel(authorization_id):
    return os.path.join(RETRY_AUTH_DIR, authorization_id + ".json")


def _retry_consumption_rel(authorization_id):
    return os.path.join(RETRY_AUTH_DIR, authorization_id + ".consumed.json")


def _retry_signature(secret, record):
    body = {key: record.get(key) for key in _RETRY_SIGNED_FIELDS}
    return hmac.new(secret, canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()


def _consumption_digest(record):
    body = {key: record.get(key) for key in _CONSUMPTION_FIELDS}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def _load_json_dict(aios_dir, rel, label):
    path = os.path.join(aios_dir, rel)
    if os.path.islink(path):
        raise TransitionError(f"{label} must not be a symlink")
    try:
        record = _load(path)
    except (OSError, ValueError) as exc:
        raise TransitionError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(record, dict):
        raise TransitionError(f"{label} failed integrity check")
    return record


def _verify_consumption_history(aios_dir, current):
    """Fail closed if any previously consumed authorization record was tampered."""
    consumed = current.get("consumed_retry_authorizations", [])
    if not isinstance(consumed, list) or len(set(map(str, consumed))) != len(consumed):
        raise TransitionError("effect retry consumption history is malformed")
    for authorization_id in consumed:
        if not isinstance(authorization_id, str) or not _RETRY_AUTH_ID.fullmatch(authorization_id):
            raise TransitionError("effect retry consumption history is malformed")
        rec = _load_json_dict(aios_dir, _retry_consumption_rel(authorization_id), "retry consumption record")
        auth = _load_json_dict(aios_dir, _retry_auth_rel(authorization_id), "consumed retry authorization")
        if (set(rec) != set(_CONSUMPTION_FIELDS) | {"digest"}
                or rec.get("record_type") != "RETRY_AUTHORIZATION_CONSUMPTION"
                or rec.get("authorization_id") != authorization_id
                or rec.get("effect_id") != current["effect_id"]
                or rec.get("digest") != _consumption_digest(rec)
                or not isinstance(auth.get("signature"), str)
                or not hmac.compare_digest(rec.get("authorization_signature") or "", auth["signature"])
                or auth.get("attempt_id") != rec.get("consumed_by_attempt_id")):
            raise TransitionError("retry consumption record failed integrity check")


def issue_retry_authorization(aios_dir, effect_id, actor, attempt, issuer, reason, *,
                              issuer_secret, keyring=None, ttl_seconds=DEFAULT_RETRY_AUTH_TTL_SECONDS, now=None):
    """Persist a signed, single-use authorization to retry one exact UNKNOWN effect state.

    ``issuer`` must be registered in the trusted keyring with the
    ``effect.retry.approve`` scope and must prove possession of its registered
    secret. It must differ from the executing actor (separation of duties).
    """
    _validate_strings(("issuer", issuer), ("reason", reason))
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    if issuer == actor:
        raise TransitionError("retry authorization issuer must differ from the executing actor (self-approval)")
    if (not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool)
            or not 0 < ttl_seconds <= MAX_RETRY_AUTH_TTL_SECONDS):
        raise ValueError("ttl_seconds must be within (0, 86400]")
    if not isinstance(issuer_secret, str) or not issuer_secret:
        raise TransitionError("retry authorization requires the issuer's signing secret")
    registered = _resolve_keyring(keyring).secret_for(issuer, RETRY_APPROVE_SCOPE)
    if not hmac.compare_digest(registered, issuer_secret.encode("utf-8")):
        raise TransitionError(f"retry issuer failed authentication: {issuer}")
    current, contract = _load_owned_effect(aios_dir, effect_id, actor, "retry authorization")
    if issuer == contract["actor"]:
        raise TransitionError("retry authorization issuer must differ from the contract actor (self-approval)")
    _verify_consumption_history(aios_dir, current)
    if current.get("state") != "UNKNOWN":
        raise TransitionError(f"retry authorization requires UNKNOWN effect, got {current.get('state')}")
    if attempt != int(current["attempt"]) + 1:
        raise TransitionError(f"retry authorization attempt must be {int(current['attempt']) + 1}, got {attempt}")
    if attempt > int(current["max_attempts"]):
        raise TransitionError("retry authorization exceeds contract attempt budget")
    issued_at = _now(now)
    authorization_id = "RA-" + secrets.token_hex(16)
    rec = {
        "record_type": "RETRY_AUTHORIZATION", "authorization_id": authorization_id,
        "effect_id": effect_id, "contract_id": current["contract_id"], "permit_id": current["permit_id"],
        "actor": actor, "issuer": issuer, "scope": RETRY_APPROVE_SCOPE,
        "effect_state_digest": _effect_state_digest(current),
        "previous_attempt": int(current["attempt"]), "previous_attempt_id": current.get("attempt_id"),
        "attempt": attempt, "attempt_id": _attempt_id(effect_id, attempt),
        "reason": reason, "unknown_reason": current.get("unknown_reason"),
        "issued_at": issued_at, "expires_at": issued_at + float(ttl_seconds),
        "mode": "EXPLICIT", "algorithm": "HMAC-SHA256",
    }
    rec["signature"] = _retry_signature(registered, rec)
    rel = _retry_auth_rel(authorization_id)
    event = {"kind": "external_effect", "action": "retry_authorized", "effect_id": effect_id,
             "authorization_id": authorization_id, "attempt": attempt, "issuer": issuer, "actor": actor}
    commit_batch(aios_dir, [(rel, rec),
                            (os.path.join("events", "effect-" + effect_id + "-RETRY-AUTH-" + authorization_id + ".json"), event)],
                 precondition=_all_of(_expect_unchanged(_effect_rel(effect_id), current),
                                      _expect_unchanged(rel, None)))
    return dict(rec)


def _verify_retry_authorization(aios_dir, supplied, current, actor, attempt, attempt_id, keyring, now):
    if isinstance(supplied, str):
        authorization_id = supplied
    elif isinstance(supplied, dict):
        authorization_id = supplied.get("authorization_id")
    else:
        authorization_id = None
    if not isinstance(authorization_id, str) or not _RETRY_AUTH_ID.fullmatch(authorization_id):
        raise TransitionError("UNKNOWN retry requires an AIOS-issued retry authorization")
    rel = _retry_auth_rel(authorization_id)
    if not os.path.lexists(os.path.join(aios_dir, rel)):
        raise TransitionError("retry authorization was not issued by AIOS")
    record = _load_json_dict(aios_dir, rel, "retry authorization record")
    if (set(record) != set(_RETRY_SIGNED_FIELDS) | {"signature"}
            or record.get("record_type") != "RETRY_AUTHORIZATION"
            or record.get("authorization_id") != authorization_id
            or record.get("mode") != "EXPLICIT" or record.get("algorithm") != "HMAC-SHA256"
            or record.get("scope") != RETRY_APPROVE_SCOPE
            or not isinstance(record.get("signature"), str)):
        raise TransitionError("retry authorization record failed integrity check")
    secret = _resolve_keyring(keyring).secret_for(record["issuer"], RETRY_APPROVE_SCOPE)
    if not hmac.compare_digest(record["signature"], _retry_signature(secret, record)):
        raise TransitionError("retry authorization record failed integrity/authenticity check")
    if record["issuer"] in (actor, current.get("actor")):
        raise TransitionError("retry authorization issuer must differ from the executing actor (self-approval)")
    if (authorization_id in current.get("consumed_retry_authorizations", [])
            or os.path.lexists(os.path.join(aios_dir, _retry_consumption_rel(authorization_id)))):
        raise TransitionError("retry authorization already consumed")
    for key, value in (("effect_id", current["effect_id"]), ("contract_id", current["contract_id"]),
                       ("permit_id", current["permit_id"]), ("actor", actor), ("attempt", attempt),
                       ("attempt_id", attempt_id), ("previous_attempt", int(current["attempt"])),
                       ("previous_attempt_id", current.get("attempt_id")),
                       ("unknown_reason", current.get("unknown_reason")),
                       ("effect_state_digest", _effect_state_digest(current))):
        if record.get(key) != value:
            raise TransitionError(f"retry authorization {key} binding mismatch")
    t = _now(now)
    if not isinstance(record["issued_at"], (int, float)) or not isinstance(record["expires_at"], (int, float)):
        raise TransitionError("retry authorization record failed integrity check")
    if t > record["expires_at"]:
        raise TransitionError("retry authorization has expired")
    if record["issued_at"] > t + _CLOCK_SKEW_SECONDS:
        raise TransitionError("retry authorization is issued in the future")
    if isinstance(supplied, dict):
        for key in supplied:
            if key not in record or supplied[key] != record[key]:
                raise TransitionError(f"supplied retry authorization differs from issued record: {key}")
    return rel, record


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt, retry_authorization=None, *,
                   keyring=None, now=None):
    """Explicitly dispatch the next attempt for an UNKNOWN effect.

    Consumes the signed retry authorization atomically with the dispatch: the
    effect CAS, the create-once consumption record and the unchanged issued
    record are all checked under the mutation lock in one commit batch.
    """
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    current, contract = _load_owned_effect(aios_dir, effect_id, actor, "retry")
    _require_provider_authorized(contract, provider)
    _verify_consumption_history(aios_dir, current)
    if current.get("state") != "UNKNOWN":
        raise TransitionError(f"retry requires UNKNOWN effect, got {current.get('state')}")
    expected = int(current.get("attempt", 0)) + 1
    if attempt != expected:
        raise TransitionError(f"retry attempt must be {expected}, got {attempt}")
    if attempt > int(current.get("max_attempts", 0)):
        raise TransitionError("retry exceeds contract attempt budget")
    if attempt_id != _attempt_id(effect_id, attempt):
        raise ValueError("attempt_id does not match retry attempt")
    auth_rel, auth = _verify_retry_authorization(aios_dir, retry_authorization, current, actor,
                                                 attempt, attempt_id, keyring, now)
    authorization_id = auth["authorization_id"]
    consumption = {
        "record_type": "RETRY_AUTHORIZATION_CONSUMPTION", "authorization_id": authorization_id,
        "authorization_signature": auth["signature"], "effect_id": effect_id,
        "consumed_by_attempt_id": attempt_id, "consumed_provider": provider,
        "consumed_from_state_digest": auth["effect_state_digest"],
    }
    consumption["digest"] = _consumption_digest(consumption)
    consumption_rel = _retry_consumption_rel(authorization_id)
    history = list(current.get("consumed_retry_authorizations", [])) + [authorization_id]
    return _transition_dispatch(aios_dir, current, actor,
                                attempt=attempt, attempt_id=attempt_id, provider=provider,
                                extra_fields={"consumed_retry_authorizations": history,
                                              "retry_authorization_id": authorization_id},
                                extra_payloads=[(consumption_rel, consumption)],
                                extra_checks=[_expect_unchanged(auth_rel, auth),
                                              _expect_unchanged(consumption_rel, None)])


def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def observation_digest(observation):
    """Content digest AIOS binds into its evidence envelope for a raw observation.

    This is integrity binding of the exact bytes AIOS accepted, NOT proof of
    who produced them.
    """
    return hashlib.sha256(json.dumps(observation, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


MAX_OBSERVATION_BYTES = 1024 * 1024
_OBSERVATION_KEYS = {"provider", "provider_operation_id", "effect_id", "attempt_id", "observation",
                     "authentication", "evidence"}
EVIDENCE_AUTHORITY = "AIOS_OBSERVE_BOUNDARY:HMAC_PROVIDER_RECEIPT+SHA256_CONTENT_BINDING"

# --- Provider receipt authority (audit F-04) --------------------------------
#
# A caller-supplied observation is an untrusted assertion. OBSERVED_* is only
# committed when the receipt carries an HMAC-SHA256 signature by the
# *dispatched* provider's key, registered in a deployment-supplied
# ProviderKeyring (``AIOS_PROVIDER_KEYRING``; never persisted in AIOS state),
# over effect, contract, permit, attempt, provider, provider operation id,
# outcome, raw-observation digest, a random receipt id and a validity window.
# Same symmetric-key limitation as core.attestation / retry authority: this
# authenticates against callers that do not hold the provider's signing key.

PROVIDER_RECEIPT_SCOPE = "provider.receipt.sign"
PROVIDER_RECEIPT_TYPE = "PROVIDER_RECEIPT_AUTHENTICATION"
MAX_PROVIDER_RECEIPT_TTL_SECONDS = 3600
_PROVIDER_RECEIPT_ID = re.compile(r"PR-[0-9a-f]{32}")
_PROVIDER_AUTH_FIELDS = ("type", "receipt_id", "contract_id", "permit_id", "issued_at", "expires_at",
                         "algorithm", "signature")
_PROVIDER_SIGNED_FIELDS = ("type", "receipt_id", "effect_id", "contract_id", "permit_id", "attempt_id",
                           "provider", "provider_operation_id", "outcome", "observation_digest",
                           "issued_at", "expires_at", "algorithm")


class ProviderAuthenticationError(TransitionError):
    """A provider receipt is missing, unauthenticated, expired or mismatched."""


class ProviderKeyring(_HmacKeyring):
    """Trusted provider receipt signers (scope ``provider.receipt.sign``)."""

    ENV_VAR = "AIOS_PROVIDER_KEYRING"
    LABEL = "provider"


def provider_receipt_body(*, receipt_id, effect_id, contract_id, permit_id, attempt_id, provider,
                          provider_operation_id, outcome, observation, issued_at, expires_at):
    """Canonical body a provider signs (shared by signer and verifier)."""
    return {
        "type": PROVIDER_RECEIPT_TYPE, "receipt_id": receipt_id, "effect_id": effect_id,
        "contract_id": contract_id, "permit_id": permit_id, "attempt_id": attempt_id,
        "provider": provider, "provider_operation_id": provider_operation_id, "outcome": outcome,
        "observation_digest": observation_digest(observation),
        "issued_at": issued_at, "expires_at": expires_at, "algorithm": "HMAC-SHA256",
    }


def provider_receipt_signature(secret: bytes, body) -> str:
    signed = {key: body.get(key) for key in _PROVIDER_SIGNED_FIELDS}
    return hmac.new(secret, canonical_json(signed).encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_provider_receipt(current, outcome, record, keyring, now):
    auth = record.get("authentication")
    if auth is None:
        raise ProviderAuthenticationError("provider receipt is not authenticated; observation is non-authoritative")
    if not isinstance(auth, dict) or set(auth) != set(_PROVIDER_AUTH_FIELDS):
        raise ProviderAuthenticationError("provider receipt authentication schema mismatch")
    if (auth["type"] != PROVIDER_RECEIPT_TYPE or auth["algorithm"] != "HMAC-SHA256"
            or not isinstance(auth["receipt_id"], str) or not _PROVIDER_RECEIPT_ID.fullmatch(auth["receipt_id"])
            or not isinstance(auth["signature"], str)
            or any(not isinstance(auth[k], (int, float)) or isinstance(auth[k], bool)
                   for k in ("issued_at", "expires_at"))):
        raise ProviderAuthenticationError("provider receipt authentication is malformed")
    if keyring is None:
        keyring = ProviderKeyring.from_env()
    if not isinstance(keyring, ProviderKeyring):
        raise ProviderAuthenticationError("observation requires a deployment-supplied trusted provider keyring")
    # The key is selected by the DISPATCHED provider, never by a claim in the receipt.
    try:
        secret = keyring.secret_for(current["provider"], PROVIDER_RECEIPT_SCOPE)
    except TransitionError as exc:
        raise ProviderAuthenticationError(str(exc)) from exc
    for key in ("contract_id", "permit_id"):
        if auth[key] != current[key]:
            raise ProviderAuthenticationError(f"provider receipt {key} binding mismatch")
    body = provider_receipt_body(
        receipt_id=auth["receipt_id"], effect_id=current["effect_id"], contract_id=current["contract_id"],
        permit_id=current["permit_id"], attempt_id=current["attempt_id"], provider=current["provider"],
        provider_operation_id=record["provider_operation_id"], outcome=outcome,
        observation=record["observation"], issued_at=auth["issued_at"], expires_at=auth["expires_at"])
    if not hmac.compare_digest(auth["signature"], provider_receipt_signature(secret, body)):
        raise ProviderAuthenticationError("provider receipt signature is invalid or not bound to this "
                                          "effect/attempt/outcome/observation")
    t = _now(now)
    if auth["expires_at"] - auth["issued_at"] > MAX_PROVIDER_RECEIPT_TTL_SECONDS or auth["expires_at"] <= auth["issued_at"]:
        raise ProviderAuthenticationError("provider receipt validity window is invalid")
    if t > auth["expires_at"]:
        raise ProviderAuthenticationError("provider receipt has expired")
    if auth["issued_at"] > t + _CLOCK_SKEW_SECONDS:
        raise ProviderAuthenticationError("provider receipt is issued in the future")
    return auth


def mint_observation_evidence(effect_id, attempt_id, provider, provider_operation_id, observation):
    """AIOS-owned evidence envelope, minted only at the observe() boundary."""
    raw_digest = observation_digest(observation)
    return EvidenceRecord(
        evidence_id="EV-" + hashlib.sha256(f"{effect_id}:{attempt_id}:{raw_digest}".encode("utf-8")).hexdigest()[:24],
        level="OBSERVED",
        source_ref=f"provider://{provider}/{provider_operation_id}",
        claim="provider returned a bounded execution observation",
        run_id=attempt_id,
        provider=provider,
        artifact_ref=raw_digest,
    ).as_record()


def observe(aios_dir, effect_id, actor, outcome, provider_observation, *, provider_keyring=None, now=None):
    """The ONLY path into OBSERVED_SUCCESS / OBSERVED_FAILURE.

    The submitted observation is untrusted. It becomes authoritative only if
    its ``authentication`` is a valid receipt signature by the dispatched
    provider's deployment-registered key, bound to this effect, contract,
    permit, attempt, provider operation, outcome and the exact raw
    observation. Otherwise ``ProviderAuthenticationError`` is raised and the
    effect is not changed. AIOS then mints its own evidence envelope; a
    caller-supplied ``evidence`` record is accepted only if identical to it.
    """
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    extra = set(provider_observation) - _OBSERVATION_KEYS
    if extra:
        raise ValueError(f"provider_observation contains unsupported fields: {sorted(extra)}")
    current, _contract = _load_owned_effect(aios_dir, effect_id, actor, "observation")
    if current.get("state") != "DISPATCHED":
        raise TransitionError("observation requires a currently DISPATCHED attempt")
    attempt_id = provider_observation.get("attempt_id")
    provider = provider_observation.get("provider")
    if attempt_id != current.get("attempt_id"):
        raise TransitionError("observation attempt does not match dispatched attempt")
    if provider != current.get("provider"):
        raise TransitionError("observation provider does not match dispatched provider")
    if provider_observation.get("effect_id") != effect_id:
        raise TransitionError("observation effect does not match effect")
    raw = provider_observation.get("observation")
    if not isinstance(raw, dict) or not raw:
        raise ValueError("observation requires a non-empty raw provider observation")
    try:
        encoded = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"raw provider observation is malformed: {exc}") from exc
    if len(encoded) > MAX_OBSERVATION_BYTES:
        raise ValueError("raw provider observation exceeds size limit")
    operation_id = provider_observation.get("provider_operation_id")
    if not isinstance(operation_id, str) or not operation_id.strip():
        raise ValueError("provider_operation_id must be a non-empty string")
    minted = mint_observation_evidence(effect_id, attempt_id, provider, operation_id, raw)
    supplied = provider_observation.get("evidence")
    if supplied is not None:
        if not isinstance(supplied, dict) or not verify_evidence(supplied):
            raise ValueError("observation requires a valid AIOS evidence record")
        if supplied.get("provider") != provider:
            raise ValueError("evidence provider does not match effect provider")
        if supplied.get("run_id") != current.get("attempt_id"):
            raise ValueError("evidence run_id is not bound to the current attempt")
        if supplied.get("artifact_ref") != minted["artifact_ref"]:
            raise ValueError("evidence artifact_ref is not bound to the provider observation")
        if canonical_json(supplied) != canonical_json(minted):
            raise ValueError("supplied evidence is not the AIOS-minted envelope for this observation")
    auth = _verify_provider_receipt(current, outcome, provider_observation, provider_keyring, now)
    record = {
        "provider": provider, "provider_operation_id": operation_id, "effect_id": effect_id,
        "attempt_id": attempt_id, "observation": raw, "provider_authentication": dict(auth),
        "evidence": minted, "evidence_authority": EVIDENCE_AUTHORITY,
    }
    return _commit_transition(aios_dir, current, actor, outcome, {"provider_observation": record})


__all__ = ["STATES", "create_effect", "transition", "dispatch", "retry_dispatch", "unknown", "observe",
           "issue_retry_authorization", "observation_digest", "mint_observation_evidence",
           "RetryIssuerKeyring", "ProviderKeyring", "ProviderAuthenticationError", "provider_receipt_body",
           "provider_receipt_signature", "PROVIDER_RECEIPT_SCOPE", "RETRY_AUTH_DIR", "RETRY_APPROVE_SCOPE", "RETRY_KEYRING_ENV"]
