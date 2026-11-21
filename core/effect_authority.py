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
import math
import os
import re
import secrets
import time
from collections.abc import Mapping

from .execution_lineage import bind_lineage_to_effect, verify_effect_lineage

from .authority import authorize, load_contract, load_permit
from .contract import verify_permit
from .evidence import EvidenceRecord, verify_evidence
from .mutation import TransitionError, canonical_json, commit_batch, recover_pending
from . import provider_ed25519 as _ed
from . import retry_ed25519 as _retry_ed

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
    binding = effect.get("execution_lineage")
    required = os.environ.get("AIOS_REQUIRE_EXECUTION_LINEAGE", "").lower() == "true"
    if required and effect.get("state") in ("DISPATCHED", "UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE") and binding is None:
        raise TransitionError("production effect is missing mandatory execution lineage")
    if binding is not None:
        try:
            verify_effect_lineage(binding, contract, effect["contract_id"], effect["permit_id"],
                                  effect.get("provider"), effect.get("attempt_id"))
        except (TypeError, ValueError) as exc:
            raise TransitionError(f"persisted execution lineage failed verification: {exc}") from exc
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
    current, _contract = _load_owned_effect(aios_dir, ef
[... 27570 bytes omitted ...]
],
                                  provider, attempt_id)
        except ValueError as exc:
            raise TransitionError(f"execution lineage rejected: {exc}") from exc
    # Verify issuer authorization first, without consuming it. Provider
    # reconciliation remains a separate mandatory gate before dispatch.
    auth_rel, auth = _verify_retry_authorization(aios_dir, retry_authorization, current, actor,
                                                 attempt, attempt_id, keyring, now)
    authorization_id = auth["authorization_id"]

    # Explicit human/issuer approval is necessary but never sufficient.
    # Require a provider-authenticated NOT_APPLIED statement for the previous
    # attempt before the next attempt can be dispatched.
    if not isinstance(not_applied_proof, Mapping):
        raise TransitionError("retry requires authenticated provider NOT_APPLIED reconciliation")
    proof = dict(not_applied_proof)
    proof_record = {
        "provider": proof.get("provider"),
        "provider_operation_id": proof.get("provider_operation_id"),
        "effect_id": proof.get("effect_id"),
        "attempt_id": proof.get("attempt_id"),
        "observation": proof.get("observation"),
        "authentication": proof.get("authentication"),
    }
    if (proof.get("outcome") != "NOT_APPLIED"
            or proof_record["effect_id"] != effect_id
            or proof_record["attempt_id"] != current.get("attempt_id")
            or proof_record["provider"] != current.get("provider")
            or not isinstance(proof_record["provider_operation_id"], str)
            or not proof_record["provider_operation_id"].strip()
            or not isinstance(proof_record["observation"], dict)
            or not proof_record["observation"]):
        raise TransitionError("NOT_APPLIED proof is not bound to the previous dispatched attempt")
    proof_auth = _verify_provider_receipt(current, "NOT_APPLIED", proof_record,
                                          provider_keyring, now, provider_public_keyring)
    proof_id = "RP-" + hashlib.sha256(canonical_json({
        "effect_id": effect_id, "attempt_id": current["attempt_id"],
        "provider": current["provider"], "provider_operation_id": proof_record["provider_operation_id"],
        "observation": proof_record["observation"], "authentication": proof_auth,
    }).encode("utf-8")).hexdigest()
    proof_record.update({"record_type": "PROVIDER_NOT_APPLIED_RECONCILIATION",
                         "outcome": "NOT_APPLIED", "proof_id": proof_id,
                         "verified_at": _now(now)})
    proof_rel = os.path.join("reconciliation_proofs", proof_id + ".json")
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
                                              "retry_authorization_id": authorization_id,
                                              "not_applied_proof_id": proof_id,
                                              **({"execution_lineage": lineage_binding} if lineage_binding else {})},
                                extra_payloads=[(consumption_rel, consumption), (proof_rel, proof_record)],
                                extra_checks=[_expect_unchanged(auth_rel, auth),
                                              _expect_unchanged(consumption_rel, None),
                                              _expect_unchanged(proof_rel, None)])


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
                           "provider", "provider_operation_id", "outcome", "observation_digest", "lineage_digest",
                           "issued_at", "expires_at", "algorithm")


class ProviderAuthenticationError(TransitionError):
    """A provider receipt is missing, unauthenticated, expired or mismatched."""


class ProviderKeyring(_HmacKeyring):
    """Trusted provider receipt signers (scope ``provider.receipt.sign``)."""

    ENV_VAR = "AIOS_PROVIDER_KEYRING"
    LABEL = "provider"


def provider_receipt_body(*, receipt_id, effect_id, contract_id, permit_id, attempt_id, provider,
                          provider_operation_id, outcome, observation, issued_at, expires_at, lineage_digest=None):
    """Canonical body a provider signs (shared by signer and verifier)."""
    return {
        "type": PROVIDER_RECEIPT_TYPE, "receipt_id": receipt_id, "effect_id": effect_id,
        "contract_id": contract_id, "permit_id": permit_id, "attempt_id": attempt_id,
        "provider": provider, "provider_operation_id": provider_operation_id, "outcome": outcome,
        "observation_digest": observation_digest(observation), "lineage_digest": lineage_digest,
        "issued_at": issued_at, "expires_at": expires_at, "algorithm": "HMAC-SHA256",
    }


def provider_receipt_signature(secret: bytes, body) -> str:
    signed = {key: body.get(key) for key in _PROVIDER_SIGNED_FIELDS}
    return hmac.new(secret, canonical_json(signed).encode("utf-8"), hashlib.sha256).hexdigest()


def _ed25519_keyring(public_keyring):
    try:
        return _ed.ProviderPublicKeyring.from_env() if public_keyring is None else public_keyring
    except ValueError as exc:
        raise ProviderAuthenticationError(str(exc)) from exc


def _check_validity_window(auth, now):
    # Fail closed on non-finite bounds: NaN compares False everywhere and
    # inf - inf is NaN, so ordinary comparisons alone would accept them.
    if not _is_finite_number(auth.get("issued_at")) or not _is_finite_number(auth.get("expires_at")):
        raise ProviderAuthenticationError("provider receipt validity window is invalid")
    t = _now(now)
    if auth["expires_at"] - auth["issued_at"] > MAX_PROVIDER_RECEIPT_TTL_SECONDS or auth["expires_at"] <= auth["issued_at"]:
        raise ProviderAuthenticationError("provider receipt validity window is invalid")
    if t > auth["expires_at"]:
        raise ProviderAuthenticationError("provider receipt has expired")
    if auth["issued_at"] > t + _CLOCK_SKEW_SECONDS:
        raise ProviderAuthenticationError("provider receipt is issued in the future")


def _verify_ed25519_receipt(current, outcome, record, public_keyring, now):
    """Ed25519-only path (audit F-04.1). No HMAC fallback; the verifier holds public keys only."""
    auth = record.get("authentication")
    if auth is None:
        raise ProviderAuthenticationError("provider receipt is not authenticated; observation is non-authoritative")
    if not isinstance(auth, dict) or set(auth) != set(_ed.ED25519_AUTH_FIELDS):
        raise ProviderAuthenticationError("Ed25519 provider receipt authentication schema mismatch "
                                          "(Ed25519 required for this provider)")
    if (auth["type"] != _ed.ED25519_RECEIPT_TYPE or auth["algorithm"] != _ed.ED25519_ALGORITHM
            or not isinstance(auth["key_id"], str)
            or not isinstance(auth["receipt_id"], str) or not _PROVIDER_RECEIPT_ID.fullmatch(auth["receipt_id"])
            or any(not _is_finite_number(auth[k]) for k in ("issued_at", "expires_at"))):
        raise ProviderAuthenticationError("Ed25519 provider receipt authentication is malformed")
    if not isinstance(public_keyring, _ed.ProviderPublicKeyring):
        raise ProviderAuthenticationError("observation requires a deployment-supplied Ed25519 public keyring")
    for key in ("contract_id", "permit_id"):
        if auth[key] != current[key]:
            raise ProviderAuthenticationError(f"provider receipt {key} binding mismatch")
    # Every signed field is rebuilt from trusted effect state + the exact raw observation.
    payload = _ed.ed25519_payload(
        key_id=auth["key_id"], receipt_id=auth["receipt_id"], effect_id=current["effect_id"],
        contract_id=current["contract_id"], permit_id=current["permit_id"], attempt_id=current["attempt_id"],
        provider=current["provider"], provider_operation_id=record["provider_operation_id"], outcome=outcome,
        observation=record["observation"], issued_at=auth["issued_at"], expires_at=auth["expires_at"],
        lineage_digest=(current.get("execution_lineage") or {}).get("lineage", {}).get("lineage_digest"))
    try:
        public_keyring.verify(current["provider"], auth["key_id"], auth["signature"], payload)
    except ValueError as exc:
        raise ProviderAuthenticationError(str(exc)) from exc
    _check_validity_window(auth, now)
    return auth


def _verify_provider_receipt(current, outcome, record, keyring, now, public_keyring=None):
    public_keyring = _ed25519_keyring(public_keyring)
    provider = current["provider"]
    if provider in _ed.ED25519_REQUIRED_PROVIDERS or (public_keyring is not None and provider in public_keyring):
        return _verify_ed25519_receipt(current, outcome, record, public_keyring, now)
    auth = record.get("authentication")
    if auth is None:
        raise ProviderAuthenticationError("provider receipt is not authenticated; observation is non-authoritative")
    if not isinstance(auth, dict) or set(auth) != set(_PROVIDER_AUTH_FIELDS):
        raise ProviderAuthenticationError("provider receipt authentication schema mismatch")
    if (auth["type"] != PROVIDER_RECEIPT_TYPE or auth["algorithm"] != "HMAC-SHA256"
            or not isinstance(auth["receipt_id"], str) or not _PROVIDER_RECEIPT_ID.fullmatch(auth["receipt_id"])
            or not isinstance(auth["signature"], str)
            or any(not _is_finite_number(auth[k]) for k in ("issued_at", "expires_at"))):
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
        observation=record["observation"], issued_at=auth["issued_at"], expires_at=auth["expires_at"],
        lineage_digest=(current.get("execution_lineage") or {}).get("lineage", {}).get("lineage_digest"))
    if not hmac.compare_digest(auth["signature"], provider_receipt_signature(secret, body)):
        raise ProviderAuthenticationError("provider receipt signature is invalid or not bound to this "
                                          "effect/attempt/outcome/observation")
    _check_validity_window(auth, now)
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


def observe(aios_dir, effect_id, actor, outcome, provider_observation, *, provider_keyring=None, now=None,
            provider_public_keyring=None):
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
    auth = _verify_provider_receipt(current, outcome, provider_observation, provider_keyring, now,
                                    provider_public_keyring)
    record = {
        "provider": provider, "provider_operation_id": operation_id, "effect_id": effect_id,
        "attempt_id": attempt_id, "observation": raw, "provider_authentication": dict(auth),
        "evidence": minted, "evidence_authority": EVIDENCE_AUTHORITY,
    }
    receipt_id = auth["receipt_id"]
    receipt_rel = os.path.join("provider_receipts", receipt_id + ".json")
    terminal_receipt = {
        "record_type": "AIOS_TERMINAL_PROVIDER_RECEIPT",
        "receipt_id": receipt_id,
        "effect_id": effect_id,
        "contract_id": current["contract_id"],
        "permit_id": current["permit_id"],
        "attempt_id": attempt_id,
        "provider": provider,
        "provider_operation_id": operation_id,
        "outcome": outcome,
        "observation": raw,
        "observation_digest": observation_digest(raw),
        "authentication": dict(auth),
        "evidence": minted,
        "evidence_authority": EVIDENCE_AUTHORITY,
        "execution_lineage": current.get("execution_lineage"),
    }
    # The immutable receipt and terminal effect transition are one journaled
    # transaction. A receipt ID can never be silently overwritten or replayed.
    return _commit_transition(
        aios_dir, current, actor, outcome, {"provider_observation": record},
        extra_payloads=[(receipt_rel, terminal_receipt)],
        extra_checks=[_expect_unchanged(receipt_rel, None)])


__all__ = ["STATES", "create_effect", "transition", "dispatch", "retry_dispatch", "unknown", "observe",
           "issue_retry_authorization", "import_retry_authorization", "observation_digest", "mint_observation_evidence",
           "RetryIssuerKeyring", "ProviderKeyring", "ProviderAuthenticationError", "provider_receipt_body",
           "provider_receipt_signature", "PROVIDER_RECEIPT_SCOPE", "RETRY_AUTH_DIR", "RETRY_APPROVE_SCOPE", "RETRY_KEYRING_ENV"]