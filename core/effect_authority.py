"""Authoritative external-effect transitions for M6.

This module is the single write boundary for provider-facing effects. An
external effect cannot be created, dispatched, retried, or observed unless the
immutable contract and permit authorize the requested effect. Identity fields
are immutable after creation; attempt IDs are deterministic and tied to the
effect/attempt number; observations must carry AIOS-owned cryptographic
evidence bound to the executing provider and attempt.

Every read-validate-write below runs under the AIOS state-tree mutation lock,
so each transition is a compare-and-set against the persisted record (no
lost updates between concurrent processes). ``claim_execution`` is the
single-use execution authorization: it atomically re-reads the persisted
effect, requires it to still be DISPATCHED for the exact attempt/provider/
actor (and the supplied snapshot identity), and records a claim so a second
caller for the same attempt is refused. It does not make provider execution
exactly-once; it only guarantees at most one AIOS-authorized invocation per
attempt and that a revoked/transitioned effect cannot be authorized.

UNKNOWN is deliberately non-terminal. It can only re-enter DISPATCHED through
the explicit retry path, subject to the contract attempt budget.
"""

import hashlib
import json
import os
import uuid

from .authority import authorize, load_contract, load_permit
from .contract import verify_permit
from .evidence import verify_evidence
from .mutation import TransitionError, canonical_json, commit_batch, mutation_lock, recover_pending

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


def _create_effect_unlocked(aios_dir, contract_id, logical_operation_id, actor, permit_id, effect_type):
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


def _transition_unlocked(aios_dir, effect_id, target, actor, **fields):
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


def _transition_dispatch(aios_dir, effect_id, actor, *, attempt, attempt_id, provider,
                         handoff_runtime=None):
    """Internal dispatch mutation after authority checks (caller holds the lock)."""
    if handoff_runtime is not None:
        _validate_strings(("handoff_runtime", handoff_runtime))
    path = _path(aios_dir, effect_id)
    current = _load(path)
    updated = dict(current)
    updated.update({"state": "DISPATCHED", "attempt": attempt,
                    "attempt_id": attempt_id, "provider": provider})
    # A new attempt never inherits a previous attempt's execution claim.
    updated.pop("execution_claim", None)
    if handoff_runtime is not None:
        updated["handoff_runtime"] = handoff_runtime
    else:
        updated.pop("handoff_runtime", None)
    event = {
        "kind": "external_effect", "action": "dispatch", "effect_id": effect_id,
        "from_state": current["state"], "to_state": "DISPATCHED", "actor": actor,
        "attempt": attempt, "attempt_id": attempt_id, "provider": provider,
        "handoff_runtime": handoff_runtime,
    }
    commit_batch(aios_dir, [(os.path.join("effects", effect_id + ".json"), updated),
                            (os.path.join("events", "effect-" + effect_id + "-DISPATCHED-attempt-" + str(attempt) + ".json"), event)])
    return updated


def _dispatch_unlocked(aios_dir, effect_id, actor, attempt_id, provider, handoff_runtime=None):
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
                                attempt=1, attempt_id=attempt_id, provider=provider,
                                handoff_runtime=handoff_runtime)


def _retry_dispatch_unlocked(aios_dir, effect_id, actor, attempt_id, provider, attempt,
                             handoff_runtime=None):
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
    contract, _permit = _validate_persisted_effect(aios_dir, current)
    return _transition_dispatch(aios_dir, effect_id, actor,
                                attempt=attempt, attempt_id=attempt_id, provider=provider,
                                handoff_runtime=handoff_runtime)


def create_effect(aios_dir, contract_id, logical_operation_id, actor, permit_id, effect_type):
    with mutation_lock(aios_dir):
        return _create_effect_unlocked(aios_dir, contract_id, logical_operation_id, actor,
                                       permit_id, effect_type)


def transition(aios_dir, effect_id, target, actor, **fields):
    with mutation_lock(aios_dir):
        return _transition_unlocked(aios_dir, effect_id, target, actor, **fields)


def dispatch(aios_dir, effect_id, actor, attempt_id, provider, handoff_runtime=None):
    """CAS PLANNED -> DISPATCHED(attempt 1).

    ``handoff_runtime`` durably names the external runtime that must schedule
    this attempt, so a crash between this commit and the runtime enqueue is
    recoverable from AIOS alone (see the runtime's reconciliation).
    """
    with mutation_lock(aios_dir):
        return _dispatch_unlocked(aios_dir, effect_id, actor, attempt_id, provider,
                                  handoff_runtime=handoff_runtime)


def retry_dispatch(aios_dir, effect_id, actor, attempt_id, provider, attempt, handoff_runtime=None):
    """CAS UNKNOWN -> DISPATCHED(attempt N); concurrent retries cannot both win."""
    with mutation_lock(aios_dir):
        return _retry_dispatch_unlocked(aios_dir, effect_id, actor, attempt_id, provider, attempt,
                                        handoff_runtime=handoff_runtime)


def observe(aios_dir, effect_id, actor, outcome, provider_observation):
    with mutation_lock(aios_dir):
        return _observe_unlocked(aios_dir, effect_id, actor, outcome, provider_observation)


class ExecutionClaimRejected(TransitionError):
    """AIOS refused to authorize provider execution; the provider was not called."""


_CLAIM_BINDING = ("effect_id", "attempt_id", "attempt", "provider", "actor",
                  "contract_id", "permit_id", "effect_type", "policy_digest")


def claim_execution(aios_dir, effect_id, attempt_id, provider, actor, holder, expected=None, *, return_authority=False):
    """Atomically authorize exactly one provider invocation for one attempt.

    Under the mutation lock: recover journals, reload the persisted effect,
    re-validate contract/permit authority, require state DISPATCHED bound to
    exactly ``(effect_id, attempt_id, provider, actor)`` (and every identity
    field of ``expected`` when given), refuse an existing claim for the same
    attempt, then durably record the claim. Returns the claimed record, which
    is the only snapshot a caller may hand to the provider.
    """
    _validate_strings(("effect_id", effect_id), ("attempt_id", attempt_id),
                      ("provider", provider), ("actor", actor), ("holder", holder))
    with mutation_lock(aios_dir):
        recover_pending(aios_dir)
        path = _path(aios_dir, effect_id)
        if not os.path.exists(path):
            raise ExecutionClaimRejected(f"unknown effect: {effect_id}")
        current = _load(path)
        try:
            contract, _permit = _validate_persisted_effect(aios_dir, current)
        except Exception as exc:
            raise ExecutionClaimRejected(f"authority no longer valid: {exc}") from exc
        # Provider permission is checked against the persisted contract, not a
        # caller-supplied contract snapshot. This check is inside the same CAS
        # critical section as the execution claim.
        if not any(isinstance(ref, str) and ref.split("@", 1)[0] == provider
                   for ref in contract.get("capabilities", [])):
            raise ExecutionClaimRejected("provider capability is not authorized by persisted contract")
        if current.get("effect_type") not in contract.get("allowed_effects", []):
            raise ExecutionClaimRejected("effect type is not authorized by persisted contract")
        if current.get("state") != "DISPATCHED":
            raise ExecutionClaimRejected(
                f"execution requires DISPATCHED, persisted state is {current.get('state')}")
        attempt = current.get("attempt")
        checks = {"effect_id": effect_id, "attempt_id": attempt_id,
                  "provider": provider, "actor": actor}
        if expected is not None:
            for key in _CLAIM_BINDING:
                if key in expected:
                    checks.setdefault(key, expected[key])
                    if expected[key] != checks[key]:
                        raise ExecutionClaimRejected(f"snapshot {key} conflicts with request")
        for key, value in checks.items():
            if current.get(key) != value:
                raise ExecutionClaimRejected(f"persisted {key} does not match execution request")
        if attempt_id != _attempt_id(effect_id, attempt):
            raise ExecutionClaimRejected("persisted attempt_id is not bound to attempt number")
        prior = current.get("execution_claim")
        if isinstance(prior, dict) and prior.get("attempt_id") == attempt_id:
            raise ExecutionClaimRejected("attempt already claimed for execution")
        claim = {"attempt_id": attempt_id, "attempt": attempt, "provider": provider,
                 "actor": actor, "holder": holder, "claim_id": "XC-" + uuid.uuid4().hex}
        updated = dict(current)
        updated["execution_claim"] = claim
        event = {"kind": "external_effect", "action": "execution_claim", "effect_id": effect_id,
                 "state": "DISPATCHED", "actor": actor, "attempt": attempt,
                 "attempt_id": attempt_id, "provider": provider, "holder": holder,
                 "claim_id": claim["claim_id"]}
        commit_batch(aios_dir, [
            (os.path.join("effects", effect_id + ".json"), updated),
            (os.path.join("events", f"effect-{effect_id}-EXECUTION-CLAIM-attempt-{attempt}.json"), event)])
        return (updated, contract) if return_authority else updated


def unknown(aios_dir, effect_id, actor, reason):
    _validate_strings(("reason", reason))
    return transition(aios_dir, effect_id, "UNKNOWN", actor, unknown_reason=reason)


def _observe_unlocked(aios_dir, effect_id, actor, outcome, provider_observation):
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
    return _transition_unlocked(aios_dir, effect_id, outcome, actor, provider_observation=provider_observation)


__all__ = ["STATES", "create_effect", "transition", "dispatch", "retry_dispatch", "unknown", "observe",
           "claim_execution", "ExecutionClaimRejected"]
