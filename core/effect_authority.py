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
from .mutation import TransitionError, canonical_json, commit_batch, file_digest, recover_pending
from .provider_trust import (
    AIOS_INVOKED_UNSIGNED, LEGACY_UNVERIFIED, OBSERVED, PROVIDER_SIGNED, RECONCILED_PREFIX, UNSIGNED,
    ProviderTrustError, attestation_payload, provider_has_trust, verify_attestation,
)
from .record_seal import require_seal, seal, seal_available, unsealed_body

EXECUTION_CLAIMS_DIR = "execution_claims"


def _claim_relpath(effect_id, attempt):
    return os.path.join(EXECUTION_CLAIMS_DIR, f"{effect_id}-attempt-{attempt}.json")

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
    _validate_persisted_provider(contract, effect)
    return contract, permit


def _validate_persisted_provider(contract, effect):
    """Re-bind the persisted provider/attempt to the contract on *every* load.

    Effect JSON lives in writable state, so ``provider`` read from disk is not
    trusted because ``dispatch()`` once checked it: a provider swapped on disk
    for one that holds a trusted signing key but is not a contract capability
    must be refused before any probe, observation or receipt
    (PR #126 re-review @218070b P1).
    """
    if effect["state"] == "PLANNED":
        if effect["attempt"] != 0 or any(k in effect for k in ("provider", "attempt_id")):
            raise TransitionError("PLANNED effect must not carry a provider or attempt identity")
        return
    provider = effect.get("provider")
    if not isinstance(provider, str) or not provider.strip():
        raise TransitionError("persisted effect has no dispatched provider")
    if not _provider_in_contract(contract, provider):
        raise TransitionError("persisted effect provider is not an authorized contract capability")
    if effect["attempt"] < 1 or effect.get("attempt_id") != _attempt_id(effect["effect_id"], effect["attempt"]):
        raise TransitionError("persisted effect attempt identity is not the derived attempt id")


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


def _effect_rel(effect_id):
    return os.path.join("effects", effect_id + ".json")


def _load_current_cas(aios_dir, effect_id):
    """Load + validate the persisted effect and the digest of the exact bytes read."""
    recover_pending(aios_dir)
    path = _path(aios_dir, effect_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    with open(path, "rb") as fh:
        raw = fh.read()
    current = json.loads(raw.decode("utf-8"))
    _validate_persisted_effect(aios_dir, current)
    if current.get("effect_id") != effect_id:
        raise TransitionError("persisted effect identity does not match its path")
    return current, hashlib.sha256(raw).hexdigest()


def _load_current(aios_dir, effect_id):
    return _load_current_cas(aios_dir, effect_id)[0]


def _provider_in_contract(contract, provider):
    return any(isinstance(ref, str) and ref.split("@", 1)[0] == provider
               for ref in contract.get("capabilities", []))


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
    current, digest = _load_current_cas(aios_dir, effect_id)
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
    commit_batch(aios_dir, [(_effect_rel(effect_id), updated),
                            (os.path.join("events", f"effect-{effect_id}-{target}-attempt-{updated.get('attempt', 0)}.json"), event)],
                 expect={_effect_rel(effect_id): digest})
    return updated


def dispatch(aios_dir, effect_id, actor, attempt_id, provider):
    _validate_strings(("attempt_id", attempt_id), ("provider", provider))
    current, digest = _load_current_cas(aios_dir, effect_id)
    if actor != current.get("actor"):
        raise TransitionError("dispatch actor does not match effect owner")
    if current.get("state") != "PLANNED":
        raise TransitionError(f"initial dispatch requires PLANNED effect, got {current.get('state')}")
    expected = _attempt_id(effect_id, 1)
    if attempt_id != expected:
        raise ValueError("attempt_id does not match initial effect attempt")
    if int(current.get("max_attempts", 0)) < 1:
        raise TransitionError("effect has no authorized execution attempts")
    contract = load_contract(aios_dir, current["contract_id"])
    if not _provider_in_contract(contract, provider):
        raise TransitionError("dispatch provider is not an authorized contract capability")
    return _transition_dispatch_with_expect(aios_dir, current, digest, actor, 1, attempt_id, provider, {})


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt, retry_authorization=None):
    """Explicitly dispatch the next attempt for a reconciled UNKNOWN effect."""
    _validate_strings(("effect_id", effect_id), ("actor", actor),
                      ("attempt_id", attempt_id), ("provider", provider))
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    current, digest = _load_current_cas(aios_dir, effect_id)
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
    # Provider substitution is not authorized by this path: the retry must go
    # to the provider that was reconciled, and that provider must still be an
    # authorized capability of the contract.
    if provider != current.get("provider"):
        raise TransitionError("retry provider differs from the reconciled provider")
    contract = load_contract(aios_dir, current["contract_id"])
    if not _provider_in_contract(contract, provider):
        raise TransitionError("retry provider is not an authorized contract capability")
    # The caller-supplied authorization is necessary but never sufficient: AIOS
    # must hold a sealed, provider-evidenced NOT_APPLIED reconciliation for the
    # exact UNKNOWN attempt being replaced.
    previous = int(current.get("attempt", 0))
    rel = _reconciliation_relpath(effect_id, previous)
    rec = load_reconciliation(aios_dir, effect_id, previous)
    if not isinstance(rec, dict) or rec.get("verdict") != "NOT_APPLIED":
        raise TransitionError("UNKNOWN retry requires a persisted NOT_APPLIED reconciliation")
    if (rec.get("source_authenticity") or {}).get("level") != PROVIDER_SIGNED:
        raise ProviderTrustError("UNKNOWN retry requires a provider-signed NOT_APPLIED reconciliation")
    if (rec.get("attempt_id") != current.get("attempt_id") or rec.get("effect_id") != effect_id
            or rec.get("attempt") != previous or rec.get("provider") != provider
            or rec.get("contract_id") != current["contract_id"] or rec.get("actor") != actor):
        raise TransitionError("reconciliation is not bound to the UNKNOWN attempt")
    rec_digest = file_digest(os.path.join(aios_dir, rel))
    updated = _transition_dispatch_with_expect(aios_dir, current, digest, actor, attempt, attempt_id,
                                              provider, {rel: rec_digest})
    return updated


def _transition_dispatch_with_expect(aios_dir, current, digest, actor, attempt, attempt_id, provider, extra_expect):
    """Dispatch mutation as compare-and-swap against the exact state that was checked.

    Two racing callers that both passed the checks cannot both dispatch: the
    loser's CAS fails under the mutation lock before any provider is called.
    """
    effect_id = current["effect_id"]
    updated = dict(current)
    updated.update({"state": "DISPATCHED", "attempt": attempt, "attempt_id": attempt_id, "provider": provider})
    updated.pop("receipt_id", None)
    event = {
        "kind": "external_effect", "action": "dispatch", "effect_id": effect_id,
        "from_state": current["state"], "to_state": "DISPATCHED", "actor": actor,
        "attempt": attempt, "attempt_id": attempt_id, "provider": provider,
    }
    commit_batch(aios_dir, [(_effect_rel(effect_id), updated),
                            (os.path.join("events", "effect-" + effect_id + "-DISPATCHED-attempt-" + str(attempt) + ".json"), event)],
                 expect={_effect_rel(effect_id): digest, **extra_expect})
    return updated


def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def _receipt_relpath(receipt_id):
    return os.path.join("receipts", receipt_id + ".json")


def _reconciliation_relpath(effect_id, attempt):
    return os.path.join("reconciliations", f"{effect_id}-attempt-{attempt}.json")


_RECEIPT_FIELDS = ("record_type", "effect_id", "attempt_id", "attempt", "contract_id", "provider",
                   "provider_operation_id", "outcome", "evidence", "recorded_via")
# Trust fields (PR #126 @18ec11f P1). Optional only so that receipts written
# before them still hash to their id; such receipts are LEGACY_UNVERIFIED and
# are never upgraded. Once present they are covered by receipt_id and seal.
_RECEIPT_TRUST_FIELDS = ("source_authenticity", "attestation")


def receipt_id_for(receipt_body):
    """Content address over every receipt field (all of _RECEIPT_FIELDS + present trust fields)."""
    allowed = set(_RECEIPT_FIELDS) | set(_RECEIPT_TRUST_FIELDS) | {"receipt_id", "seal", "sealed"}
    if not isinstance(receipt_body, dict) or set(receipt_body) - allowed:
        raise ValueError("receipt body has unexpected fields")
    missing = [k for k in _RECEIPT_FIELDS if k not in receipt_body]
    if missing:
        raise ValueError(f"receipt body is missing fields: {missing}")
    if ("source_authenticity" in receipt_body) != ("attestation" in receipt_body):
        raise ValueError("receipt trust fields must be recorded together")
    value = {k: receipt_body[k] for k in (*_RECEIPT_FIELDS, *_RECEIPT_TRUST_FIELDS) if k in receipt_body}
    return "RC-" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def receipt_source_authenticity(receipt):
    """Trust level of a persisted receipt; legacy receipts are never upgraded."""
    stamp = receipt.get("source_authenticity") if isinstance(receipt, dict) else None
    return stamp.get("level") if isinstance(stamp, dict) else LEGACY_UNVERIFIED


def _observation_trust(aios_dir, current, outcome, provider_observation, evidence, op_id, *, invoked):
    """SOURCE_AUTHENTICITY for an observation. SHA-256 evidence alone is never enough.

    * attested: provider signature over the AIOS-built statement => PROVIDER_SIGNED;
    * unsigned, AIOS-invoked execution of a provider with *no* trusted keys =>
      AIOS_INVOKED_UNSIGNED (recorded as such, never unlocks retry);
    * anything else is refused, including an unsigned observation for a
      provider that has trusted keys (downgrade) and every direct ``observe()``
      call without an attestation.
    """
    provider = current.get("provider")
    attestation = provider_observation.get("attestation")
    if attestation is not None:
        payload = attestation_payload(
            provider=provider, effect_id=current["effect_id"], attempt_id=current.get("attempt_id"),
            statement=OBSERVED, evidence=evidence, outcome=outcome, provider_operation_id=op_id,
            observation=provider_observation.get("observation"))
        return verify_attestation(attestation, payload, aios_dir)
    if not invoked:
        raise ProviderTrustError(
            "observation requires a provider-signed attestation: a SHA-256 evidence digest proves "
            "content integrity only, not that the provider issued it")
    if provider_has_trust(provider, aios_dir):
        raise ProviderTrustError("provider has trusted keys; unsigned observation is refused (downgrade)")
    return {"level": AIOS_INVOKED_UNSIGNED}


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
    if evidence.get("run_id") != attempt_id:
        raise ValueError("observation evidence is not bound to the dispatched attempt")
    op_id = provider_observation.get("provider_operation_id")
    if not isinstance(op_id, str) or not op_id.strip():
        raise ValueError("provider_operation_id is required for an observed outcome")
    return attempt_id, provider, evidence, op_id


def _commit_observation(aios_dir, current, digest, actor, outcome, provider_observation, via,
                        extra=(), extra_expect=None, *, invoked=False):
    # Defence in depth: never record an outcome for a provider the stored
    # contract does not authorize, whatever the caller path.
    if not _provider_in_contract(load_contract(aios_dir, current["contract_id"]), current.get("provider")):
        raise TransitionError("observation provider is not an authorized contract capability")
    attempt_id, provider, evidence, op_id = _validated_observation(current, outcome, provider_observation)
    trust = _observation_trust(aios_dir, current, outcome, provider_observation, evidence, op_id,
                               invoked=invoked)
    effect_id = current["effect_id"]
    body = {
        "record_type": "PROVIDER_RECEIPT", "effect_id": effect_id,
        "attempt_id": attempt_id, "attempt": current["attempt"], "contract_id": current["contract_id"],
        "provider": provider, "provider_operation_id": op_id, "outcome": outcome,
        "evidence": evidence, "recorded_via": via,
        "source_authenticity": trust, "attestation": provider_observation.get("attestation"),
    }
    rid = receipt_id_for(body)
    receipt = {**body, "receipt_id": rid}
    # Seal when the deployment key is configured. Unsealed receipts are kept
    # (so existing adapters keep recording observations) but no authority
    # consumer (evaluation, retry) trusts them.
    receipt = seal(receipt) if seal_available() else {**receipt, "sealed": False}
    updated = dict(current)
    updated.update({"state": outcome, "provider_observation": provider_observation, "receipt_id": rid})
    event = {
        "kind": "external_effect", "action": "observe", "effect_id": effect_id,
        "from_state": current["state"], "to_state": outcome, "actor": actor,
        "attempt": current["attempt"], "attempt_id": attempt_id, "receipt_id": rid, "via": via,
    }
    expect = {_effect_rel(effect_id): digest, _receipt_relpath(rid): None}
    expect.update(extra_expect or {})
    commit_batch(aios_dir, [
        *extra,
        (_receipt_relpath(rid), receipt),
        (_effect_rel(effect_id), updated),
        (os.path.join("events", f"effect-{effect_id}-{outcome}-attempt-{current['attempt']}.json"), event),
    ], expect=expect)
    return updated


def observe(aios_dir, effect_id, actor, outcome, provider_observation):
    """Record a provider observation submitted by a caller.

    Requires ``provider_observation['attestation']`` signed by a key trusted for
    the dispatched provider. A caller-built EvidenceRecord with a correct
    digest is refused (PR #126 @18ec11f P1, path A).
    """
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    current, digest = _load_current_cas(aios_dir, effect_id)
    if actor != current.get("actor"):
        raise TransitionError("observation actor does not match effect owner")
    if current.get("state") != "DISPATCHED":
        raise TransitionError("observation requires a currently DISPATCHED attempt")
    return _commit_observation(aios_dir, current, digest, actor, outcome, provider_observation, "observe")


def _observe_invoked(aios_dir, effect_id, actor, outcome, provider_observation):
    """Runtime-internal: record what the adapter AIOS itself invoked returned.

    Bound to the at-most-once execution claim for the exact dispatched attempt
    (CAS on the claim bytes). Unsigned results are recorded as
    AIOS_INVOKED_UNSIGNED only for providers without trusted keys.
    """
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("invalid observation outcome")
    if not isinstance(provider_observation, dict) or not provider_observation:
        raise ValueError("provider_observation must be a non-empty dict")
    current, digest = _load_current_cas(aios_dir, effect_id)
    if actor != current.get("actor"):
        raise TransitionError("observation actor does not match effect owner")
    if current.get("state") != "DISPATCHED":
        raise TransitionError("observation requires a currently DISPATCHED attempt")
    rel = _claim_relpath(effect_id, current.get("attempt", 0))
    path = os.path.join(aios_dir, rel)
    if not os.path.exists(path):
        raise TransitionError("AIOS-invoked observation requires the execution claim for this attempt")
    claim = _load(path)
    if (claim.get("kind") != "execution_claim" or claim.get("effect_id") != effect_id
            or claim.get("attempt_id") != current.get("attempt_id")
            or claim.get("provider") != current.get("provider") or claim.get("actor") != actor):
        raise TransitionError("execution claim is not bound to the dispatched attempt")
    return _commit_observation(aios_dir, current, digest, actor, outcome, provider_observation, "observe",
                               extra_expect={rel: file_digest(path)}, invoked=True)


def _verify_receipt_attestation(aios_dir, receipt, effect):
    stamp = receipt.get("source_authenticity")
    level = stamp.get("level") if isinstance(stamp, dict) else None
    if level == PROVIDER_SIGNED:
        observation = (effect.get("provider_observation") or {}).get("observation")
        payload = attestation_payload(
            provider=receipt["provider"], effect_id=receipt["effect_id"], attempt_id=receipt["attempt_id"],
            statement=OBSERVED, evidence=receipt["evidence"], outcome=receipt["outcome"],
            provider_operation_id=receipt["provider_operation_id"], observation=observation)
        verify_attestation(receipt.get("attestation"), payload, aios_dir)
    elif level == AIOS_INVOKED_UNSIGNED:
        if receipt.get("attestation") is not None:
            raise TransitionError("unsigned receipt carries an attestation")
    else:
        raise TransitionError(f"persisted receipt has unknown source authenticity: {level}")


def load_receipt(aios_dir, receipt_id, *, require_sealed=True, require_provider_signed=False):
    """Load a persisted receipt and verify content, seal and receipt-of-record binding."""
    _validate_strings(("receipt_id", receipt_id))
    recover_pending(aios_dir)  # never read a half-applied batch
    path = os.path.join(aios_dir, _receipt_relpath(receipt_id))
    if not os.path.exists(path):
        raise KeyError(f"unknown receipt: {receipt_id}")
    receipt = _load(path)
    if receipt.get("record_type") != "PROVIDER_RECEIPT":
        raise TransitionError("persisted record is not a provider receipt")
    if require_sealed:
        require_seal(receipt, "provider receipt")
    evidence = receipt.get("evidence")
    if not isinstance(evidence, dict) or not verify_evidence(evidence):
        raise TransitionError("persisted receipt evidence is invalid")
    try:
        expected = receipt_id_for(unsealed_body(receipt))
    except ValueError as exc:
        raise TransitionError(f"persisted receipt identity does not match its content: {exc}") from exc
    if expected != receipt_id or receipt.get("receipt_id") != receipt_id:
        raise TransitionError("persisted receipt identity does not match its content")
    if evidence.get("run_id") != receipt.get("attempt_id") or evidence.get("provider") != receipt.get("provider"):
        raise TransitionError("persisted receipt evidence is not bound to its attempt/provider")
    effect = _load(_path(aios_dir, receipt["effect_id"]))
    if effect.get("receipt_id") != receipt_id:
        raise TransitionError("persisted receipt is not the receipt of record for its effect")
    for field in ("attempt_id", "attempt", "contract_id", "provider"):
        if effect.get(field) != receipt.get(field):
            raise TransitionError(f"persisted receipt {field} differs from its effect")
    if effect.get("state") != receipt["outcome"]:
        raise TransitionError("persisted receipt outcome differs from effect state")
    if "source_authenticity" in receipt:
        # Re-verified on every load: a revoked provider key revokes the receipt.
        _verify_receipt_attestation(aios_dir, receipt, effect)
    if require_provider_signed and receipt_source_authenticity(receipt) != PROVIDER_SIGNED:
        raise ProviderTrustError(
            f"receipt source authenticity is {receipt_source_authenticity(receipt)}, provider signature required")
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
DECISIVE_VERDICTS = ("APPLIED", "NOT_APPLIED")


def _reconciliation_payload(effect_id, attempt_id, provider, verdict, evidence, outcome):
    return attestation_payload(provider=provider, effect_id=effect_id, attempt_id=attempt_id,
                               statement=RECONCILED_PREFIX + verdict, evidence=evidence,
                               outcome=outcome if verdict == "APPLIED" else None)


def load_reconciliation(aios_dir, effect_id, attempt):
    """Return the sealed reconciliation for an attempt, or None. Forged/unsealed records raise."""
    recover_pending(aios_dir)
    path = os.path.join(aios_dir, _reconciliation_relpath(effect_id, attempt))
    if not os.path.exists(path):
        return None
    record = _load(path)
    if record.get("record_type") != "EFFECT_RECONCILIATION":
        raise TransitionError("persisted record is not an effect reconciliation")
    require_seal(record, "effect reconciliation")
    evidence = record.get("evidence")
    if not isinstance(evidence, dict) or not verify_evidence(evidence):
        raise TransitionError("reconciliation evidence is invalid")
    if (record.get("effect_id") != effect_id or record.get("attempt") != attempt
            or evidence.get("run_id") != record.get("attempt_id")
            or evidence.get("provider") != record.get("provider")):
        raise TransitionError("reconciliation record is not bound to its attempt/provider")
    if record.get("verdict") in DECISIVE_VERDICTS:
        # A decisive verdict (NOT_APPLIED unlocks retry) needs SOURCE_AUTHENTICITY,
        # re-verified against the current trust store. Records written before
        # provider attestation existed are not upgraded (PR #126 @18ec11f P1).
        stamp = record.get("source_authenticity")
        if not isinstance(stamp, dict) or stamp.get("level") != PROVIDER_SIGNED:
            raise ProviderTrustError("decisive reconciliation lacks provider-signed source authenticity")
        verify_attestation(record.get("attestation"), _reconciliation_payload(
            effect_id, record.get("attempt_id"), record.get("provider"), record["verdict"], evidence,
            record.get("outcome")), aios_dir)
    return record


def reconcile_effect(aios_dir, effect_id, actor, verdict, provider_evidence, *,
                     outcome=None, provider_observation=None, attestation=None):
    """Record a sealed AIOS reconciliation verdict for the current UNKNOWN attempt.

    * APPLIED: requires ``outcome`` and a full ``provider_observation``; the
      effect leaves UNKNOWN with a persisted receipt. It is never retried.
    * NOT_APPLIED: requires provider evidence bound to the exact attempt; this
      sealed record is the only artefact that unlocks ``retry_dispatch``.
    * INCONCLUSIVE: recorded as negative evidence; the effect stays UNKNOWN
      and retry stays blocked.

    APPLIED and NOT_APPLIED additionally require ``attestation``: a provider
    signature (trusted key, ``core.provider_trust``) over the AIOS-built
    statement (effect, attempt, provider, verdict, evidence digest[, outcome]).
    APPLIED also requires the observation itself to be attested. A caller that
    merely recomputes an EvidenceRecord digest cannot produce either
    (PR #126 @18ec11f P1, path B). INCONCLUSIVE may be unsigned: it only keeps
    the effect blocked.

    Fails closed (SealError) when the deployment seal key is not configured.
    """
    if verdict not in RECONCILIATION_VERDICTS:
        raise ValueError("invalid reconciliation verdict")
    current, digest = _load_current_cas(aios_dir, effect_id)
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
    if verdict == "APPLIED" and outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("APPLIED reconciliation requires outcome and provider_observation")
    payload = _reconciliation_payload(effect_id, attempt_id, provider, verdict, provider_evidence, outcome)
    if attestation is not None:
        trust = verify_attestation(attestation, payload, aios_dir)
    elif verdict in DECISIVE_VERDICTS:
        raise ProviderTrustError(
            f"{verdict} reconciliation requires a provider-signed attestation; a SHA-256 evidence "
            "digest proves content integrity only")
    else:
        trust = {"level": UNSIGNED}
    rel = _reconciliation_relpath(effect_id, attempt)
    rec_digest = file_digest(os.path.join(aios_dir, rel))
    existing = load_reconciliation(aios_dir, effect_id, attempt)
    if existing is not None and existing.get("verdict") in ("APPLIED", "NOT_APPLIED"):
        raise TransitionError("attempt already has a decisive reconciliation verdict")
    record = seal({
        "record_type": "EFFECT_RECONCILIATION", "effect_id": effect_id, "attempt": attempt,
        "attempt_id": attempt_id, "contract_id": current["contract_id"], "provider": provider,
        "verdict": verdict, "evidence": provider_evidence, "actor": actor,
        "outcome": outcome if verdict == "APPLIED" else None,
        "attestation": attestation, "source_authenticity": trust,
        "supersedes": existing.get("evidence", {}).get("digest") if existing else None,
    })
    cas = {rel: rec_digest}
    if verdict == "APPLIED":
        if outcome is None or provider_observation is None:
            raise ValueError("APPLIED reconciliation requires outcome and provider_observation")
        return _commit_observation(aios_dir, current, digest, actor, outcome, provider_observation,
                                   "reconciliation", extra=[(rel, record)], extra_expect=cas)
    if outcome is not None or provider_observation is not None:
        raise ValueError("only APPLIED reconciliation may carry an observation")
    event = {"kind": "external_effect", "action": "reconcile", "effect_id": effect_id,
             "attempt": attempt, "attempt_id": attempt_id, "verdict": verdict, "actor": actor}
    commit_batch(aios_dir, [(rel, record),
                            (os.path.join("events", f"effect-{effect_id}-reconcile-{attempt}-{verdict}-{record['seal']['mac'][:12]}.json"), event)],
                 expect={_effect_rel(effect_id): digest, **cas})
    return record


__all__ = ["STATES", "RECONCILIATION_VERDICTS", "DECISIVE_VERDICTS", "receipt_source_authenticity", "create_effect", "transition", "dispatch", "retry_dispatch",
           "unknown", "observe", "receipt_id_for", "load_receipt", "recover_interrupted",
           "reconcile_effect", "load_reconciliation"]
