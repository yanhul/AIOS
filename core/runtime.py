"""Thin AIOS provider boundary.

AIOS owns authority and evidence semantics. Durable scheduling, retries,
resume, planning and agent loops belong to an external execution substrate.
"""

from dataclasses import dataclass
from typing import Protocol
import hashlib
import json
import os

from .evidence import EvidenceRecord
from .authority import _canonical_contract, authorize, load_contract, load_permit
from .contract import contract_identity
from .capabilities import CapabilityRegistry
from .durable_runtime import DurableRuntime, validate_submission
from .effect_authority import (
    EXECUTION_CLAIMS_DIR, create_effect, dispatch, load_reconciliation, reconcile_effect, recover_interrupted,
    retry_dispatch, unknown, _claim_relpath, _effect_rel, _load_current, _load_current_cas, _observe_invoked,
)
from .mutation import TransitionError, canonical_json, commit_batch
from .provider_trust import ProviderTrustError


@dataclass(frozen=True)
class ProviderReceipt:
    provider: str
    effect_id: str
    attempt_id: str
    provider_operation_id: str
    outcome: str
    observation: dict
    # Provider signature over the observation statement (core.provider_trust).
    # Required when the provider has trusted keys configured.
    attestation: "dict | None" = None


@dataclass(frozen=True)
class ReconciliationReport:
    """Provider-side answer to "did attempt X take effect?".

    ``verdict`` is APPLIED, NOT_APPLIED or INCONCLUSIVE. ``evidence`` must be an
    AIOS evidence record bound to the queried attempt. APPLIED must also carry
    the ProviderReceipt for the operation that was found.
    """
    verdict: str
    evidence: dict
    receipt: "ProviderReceipt | None" = None
    # Provider signature over the verdict statement. Required for APPLIED and
    # NOT_APPLIED; without it the probe answer is not recorded.
    attestation: "dict | None" = None


class ProviderAdapter(Protocol):
    name: str

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        """Execute exactly one already-authorized provider operation."""
        ...


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _provider_authorized(contract, provider_name):
    return any(
        isinstance(ref, str) and ref.split("@", 1)[0] == provider_name
        for ref in contract.get("capabilities", [])
    )


IDEMPOTENT_ATTEMPT_IDS_KEY = "idempotent_attempt_ids"


def _registry_attests_idempotent_resume(aios_dir, persisted_effect, provider_name):
    """True only if AIOS authority -- not the adapter object -- attests dedupe.

    Re-sending a DISPATCHED attempt is safe only when the provider dedupes on
    ``attempt_id``. That is a property of a specific provider capability
    *version*, so it is read from the AIOS capability registry entry that the
    persisted contract (loaded by the effect's own ``contract_id``, never the
    caller-supplied dict) binds for this provider, and only from a registry
    carrying a valid AIOS seal. An adapter's own
    ``idempotent_attempt_ids`` attribute is necessary but never sufficient.
    Any lookup failure fails closed to reconciliation.
    """
    try:
        contract = load_contract(aios_dir, persisted_effect["contract_id"])
        refs = [ref for ref in contract.get("capabilities", [])
                if isinstance(ref, str) and ref.split("@", 1)[0] == provider_name]
        if len(refs) != 1:
            return False
        # Only a registry sealed at the AIOS write boundary may grant this.
        capability = CapabilityRegistry.load(aios_dir, require_sealed=True).require(refs[0])
    except Exception:  # noqa: BLE001 - any authority doubt => reconcile, never re-execute
        return False
    return dict(capability.metadata).get(IDEMPOTENT_ATTEMPT_IDS_KEY) == "true"


def _submit_runtime(runtime, method, effect, attempt_id, provider_name, **kwargs):
    """Bridge an already-authorized attempt into an external durable runtime."""
    if runtime is None:
        return None
    if not hasattr(runtime, method):
        raise ValueError(f"durable runtime must implement {method}")
    submission = getattr(runtime, method)(effect=dict(effect), attempt_id=attempt_id, **kwargs)
    validate_submission(effect, submission, attempt_id, provider_name)
    return submission


def validate_receipt(receipt, effect, attempt_id, provider_name):
    """Fail closed unless the provider explicitly observed a bound outcome."""
    if not isinstance(receipt, ProviderReceipt):
        raise ValueError("provider must return ProviderReceipt")
    _text(receipt.provider, "receipt.provider")
    _text(receipt.effect_id, "receipt.effect_id")
    _text(receipt.attempt_id, "receipt.attempt_id")
    _text(receipt.provider_operation_id, "receipt.provider_operation_id")
    if receipt.effect_id != effect["effect_id"]:
        raise ValueError("receipt effect binding mismatch")
    if receipt.attempt_id != attempt_id:
        raise ValueError("receipt attempt binding mismatch")
    if receipt.provider != provider_name:
        raise ValueError("receipt provider binding mismatch")
    if receipt.outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("receipt outcome must be an observed terminal outcome")
    if not isinstance(receipt.observation, dict) or not receipt.observation:
        raise ValueError("receipt observation must be a non-empty dict")


def _provider_observation(receipt):
    provider_observation = {
        "provider": receipt.provider,
        "provider_operation_id": receipt.provider_operation_id,
        "effect_id": receipt.effect_id,
        "attempt_id": receipt.attempt_id,
        "observation": receipt.observation,
    }
    if receipt.attestation is not None:
        provider_observation["attestation"] = receipt.attestation
    supplied = receipt.observation.get("evidence")
    if isinstance(supplied, dict):
        provider_observation["evidence"] = supplied
    else:
        # The ProviderReceipt is the raw provider observation. Wrap that raw
        # receipt as OBSERVED evidence at the AIOS observation boundary; do not
        # derive verification, truth, or PASS from it.
        raw_digest = hashlib.sha256(
            json.dumps(
                receipt.observation,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        provider_observation["evidence"] = EvidenceRecord(
            evidence_id="EV-" + hashlib.sha256(
                f"{receipt.effect_id}:{receipt.attempt_id}:{raw_digest}".encode("utf-8")
            ).hexdigest()[:24],
            level="OBSERVED",
            source_ref=f"provider://{receipt.provider}/{receipt.provider_operation_id}",
            claim="provider returned a bounded execution observation",
            run_id=receipt.attempt_id,
            provider=receipt.provider,
            artifact_ref=raw_digest,
        ).as_record()
    return provider_observation


def _bind_persisted(aios_dir, contract, effect, actor, attempt_id, provider_name):
    """Bind an execution request to the *persisted* effect and contract.

    Returns ``(stored_contract, persisted_effect, effect_digest)``. Nothing the
    caller supplies is ever handed to the provider:

    * the caller contract must have the identity of the contract persisted on
      the effect, and the stored contract is what is used (PR #126 @9fd7d5c);
    * the caller effect must be byte-for-byte (canonically) the persisted
      effect, which must still be DISPATCHED for exactly this attempt, actor
      and provider. A stale DISPATCHED copy kept after the attempt was
      observed, or a copy with edited fields, is refused before the provider
      is called (PR #126 re-review @444e578 F3).
    """
    effect_id = effect.get("effect_id")
    _text(effect_id, "effect.effect_id")
    persisted, digest = _load_current_cas(aios_dir, effect_id)
    if persisted.get("state") != "DISPATCHED":
        raise RuntimeError(f"persisted effect is not DISPATCHED (state={persisted.get('state')}); refusing to execute")
    if persisted.get("attempt_id") != attempt_id:
        raise RuntimeError("persisted effect is no longer the dispatched attempt being executed")
    if persisted.get("actor") != actor:
        raise PermissionError("persisted effect actor does not match execution actor")
    if persisted.get("provider") != provider_name:
        raise PermissionError("execution provider differs from the dispatched provider")
    if canonical_json(effect) != canonical_json(persisted):
        raise PermissionError("caller effect differs from the persisted effect; refusing to execute")
    bound_id = persisted.get("contract_id")
    try:
        caller_id = contract_identity(_canonical_contract(contract))
    except Exception as exc:  # noqa: BLE001 - malformed caller contract => refuse
        raise PermissionError(f"caller contract is not a valid execution contract: {exc}") from exc
    if not isinstance(bound_id, str) or caller_id != bound_id:
        raise PermissionError("caller contract differs from the contract bound to the effect")
    stored = load_contract(aios_dir, bound_id)
    if not _provider_authorized(stored, provider_name):
        raise PermissionError("provider capability is not authorized by contract")
    if "external_effect" not in stored.get("allowed_effects", []):
        raise PermissionError("external effect is not authorized by contract")
    return stored, persisted, digest


def _claim_execution(aios_dir, persisted, digest, actor):
    """At-most-once claim of one dispatched attempt, as CAS under the mutation lock.

    The claim is written only if the effect bytes are still exactly the ones
    that were validated *and* no claim for this attempt exists. Two concurrent
    callers (or a replay of the same call) cannot both reach the provider; the
    loser fails before any side effect. A crash after the claim leaves the
    effect DISPATCHED with a claim: only ``resume_attempt`` may continue it,
    and only via registry-attested idempotency or reconciliation.
    """
    rel = _claim_relpath(persisted["effect_id"], persisted.get("attempt", 0))
    claim = {
        "kind": "execution_claim", "effect_id": persisted["effect_id"],
        "attempt": persisted.get("attempt"), "attempt_id": persisted["attempt_id"],
        "provider": persisted["provider"], "actor": actor,
    }
    try:
        commit_batch(aios_dir, [(rel, claim)],
                     expect={_effect_rel(persisted["effect_id"]): digest, rel: None})
    except TransitionError as exc:
        raise RuntimeError(f"attempt already claimed or effect changed concurrently: {exc}") from exc


def _ensure_claim(aios_dir, persisted, digest, actor):
    """Idempotent-resume only: reuse the attempt's claim, or write it if none exists.

    The provider dedupes on attempt_id (registry-attested), so re-sending under
    an existing claim is safe; the claim still binds the observation that
    follows to this exact attempt/provider/actor.
    """
    path = os.path.join(aios_dir, _claim_relpath(persisted["effect_id"], persisted.get("attempt", 0)))
    if not os.path.exists(path):
        _claim_execution(aios_dir, persisted, digest, actor)
        return
    with open(path, "r", encoding="utf-8") as fh:
        claim = json.load(fh)
    if (claim.get("attempt_id") != persisted["attempt_id"] or claim.get("provider") != persisted["provider"]
            or claim.get("actor") != actor):
        raise PermissionError("existing execution claim is bound to another attempt/provider/actor")


def _run_bound(aios_dir, stored_contract, persisted, actor, adapter, provider_name):
    attempt_id = persisted["attempt_id"]
    try:
        receipt = adapter.execute(contract=dict(stored_contract), effect=dict(persisted), attempt_id=attempt_id)
        validate_receipt(receipt, persisted, attempt_id, provider_name)
    except Exception as exc:
        return unknown(aios_dir, persisted["effect_id"], actor,
                       f"provider ambiguity: {type(exc).__name__}: {exc}")
    provider_observation = _provider_observation(receipt)
    try:
        return _observe_invoked(aios_dir, persisted["effect_id"], actor, receipt.outcome, provider_observation)
    except ProviderTrustError as exc:
        # The provider was called and may have applied the effect, but its
        # answer is not authenticated: never success, never silently retried.
        return unknown(aios_dir, persisted["effect_id"], actor,
                       f"provider observation not authenticated: {exc}")


def execute_attempt(aios_dir, contract, effect, actor, adapter, attempt_id):
    """Execute exactly one dispatched attempt and record its observation.

    At most once per attempt: the persisted effect is bound and an execution
    claim is committed (CAS) before the provider is called. Re-execution after
    a crash is only possible through ``resume_attempt``.
    """
    _text(actor, "actor")
    _text(attempt_id, "attempt_id")
    if not isinstance(contract, dict) or not contract:
        raise ValueError("contract must be a non-empty dict")
    if not isinstance(effect, dict) or not effect:
        raise ValueError("effect must be a non-empty dict")
    if effect.get("state") != "DISPATCHED":
        raise RuntimeError("effect must be DISPATCHED before execute_attempt")
    if effect.get("actor") != actor:
        raise PermissionError("effect actor does not match execution actor")
    if effect.get("attempt_id") != attempt_id:
        raise RuntimeError("attempt_id does not match dispatched effect")
    if not hasattr(adapter, "name"):
        raise ValueError("adapter must expose a provider name")
    provider_name = _text(adapter.name, "adapter.name")
    stored, persisted, digest = _bind_persisted(aios_dir, contract, effect, actor, attempt_id, provider_name)
    _claim_execution(aios_dir, persisted, digest, actor)
    return _run_bound(aios_dir, stored, persisted, actor, adapter, provider_name)


def resume_attempt(aios_dir, contract, effect, actor, adapter, durable_runtime: DurableRuntime):
    """Resume a DISPATCHED attempt that has no receipt (e.g. after a crash).

    Re-sending the same attempt to the provider is only safe when the provider
    guarantees deduplication on attempt_id. That must be attested by AIOS: the
    contract-bound capability version in the capability registry carries
    metadata ``idempotent_attempt_ids=true`` *and* the adapter declares
    ``idempotent_attempt_ids = True``. Self-declaration alone is ignored. Otherwise AIOS never re-executes: the
    attempt becomes UNKNOWN and is reconciled through the provider status
    probe (APPLIED -> receipt, NOT_APPLIED -> eligible for an explicit retry
    with a new attempt identity, INCONCLUSIVE -> blocked).
    """
    _text(actor, "actor")
    if not isinstance(contract, dict) or not contract:
        raise ValueError("contract must be a non-empty dict")
    if not isinstance(effect, dict) or not effect:
        raise ValueError("effect must be a non-empty dict")
    if effect.get("state") != "DISPATCHED":
        raise RuntimeError("effect must be DISPATCHED before resume_attempt")
    attempt_id = effect.get("attempt_id")
    _text(attempt_id, "effect.attempt_id")
    if effect.get("actor") != actor:
        raise PermissionError("effect actor does not match execution actor")
    provider_name = _text(getattr(adapter, "name", None), "adapter.name")
    if not _provider_authorized(contract, provider_name):
        raise PermissionError("provider capability is not authorized by contract")
    if "external_effect" not in contract.get("allowed_effects", []):
        raise PermissionError("external effect is not authorized by contract")
    # Never hand an attempt dispatched to provider A to provider B -- not for
    # re-execution and not for reconciliation (PR #126 re-review F3/F5); the
    # caller effect must be the persisted one (PR #126 @444e578 F3).
    stored, persisted, _digest = _bind_persisted(aios_dir, contract, effect, actor, attempt_id, provider_name)
    if _registry_attests_idempotent_resume(aios_dir, persisted, provider_name) and \
            getattr(adapter, "idempotent_attempt_ids", False) is True:
        # Re-sending is safe only because AIOS-sealed authority attests that
        # the provider dedupes on attempt_id; this is the ONLY path allowed to
        # run an already-claimed attempt again.
        _submit_runtime(durable_runtime, "resume", persisted, attempt_id, provider_name)
        _ensure_claim(aios_dir, persisted, _digest, actor)
        return _run_bound(aios_dir, stored, persisted, actor, adapter, provider_name)
    recover_interrupted(aios_dir, effect["effect_id"], actor,
                        "resume of non-idempotent provider attempt; reconciliation required")
    return reconcile_unknown_attempt(aios_dir, effect["effect_id"], actor, adapter)


def execute_retry_attempt(aios_dir, contract_id, permit_id, effect, actor, adapter, attempt_id, attempt,
                          durable_runtime: DurableRuntime | None = None):
    """Authorize, dispatch and execute one explicit retry of an UNKNOWN effect.

    The external runtime may schedule/persist the attempt, but AIOS remains the
    authority boundary for authorization, attempt bounds and evidence acceptance.
    """
    _text(actor, "actor")
    _text(attempt_id, "attempt_id")
    if not isinstance(effect, dict) or not effect:
        raise ValueError("effect must be a non-empty dict")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 2:
        raise ValueError("retry attempt must be an integer >= 2")
    if effect.get("contract_id") != contract_id:
        raise PermissionError("effect contract binding mismatch")
    if effect.get("actor") != actor:
        raise PermissionError("effect actor does not match execution actor")
    if effect.get("state") != "UNKNOWN":
        raise RuntimeError("effect must be UNKNOWN before retry")
    # UNKNOWN is ambiguous by definition: retry is forbidden unless the persisted
    # effect carries an explicit, governed retry authorization. A provider timeout
    # alone is not proof that no external effect occurred.
    retry_auth = effect.get("retry_authorization")
    if not isinstance(retry_auth, dict) or retry_auth.get("mode") != "EXPLICIT":
        raise PermissionError("UNKNOWN effect requires explicit retry authorization")
    if retry_auth.get("effect_id") != effect.get("effect_id"):
        raise PermissionError("retry authorization effect binding mismatch")
    if retry_auth.get("attempt") != attempt:
        raise PermissionError("retry authorization attempt mismatch")

    authorize(aios_dir, contract_id, permit_id)
    contract = load_contract(aios_dir, contract_id)
    permit = load_permit(aios_dir, permit_id)
    if permit["actor"] != actor or contract["actor"] != actor:
        raise PermissionError("actor does not match authorized contract")
    max_attempts = contract.get("max_attempts")
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise ValueError("contract max_attempts must be a positive integer")
    if attempt > max_attempts:
        raise PermissionError("retry exceeds contract max_attempts")
    provider_name = _text(getattr(adapter, "name", None), "adapter.name")
    if not _provider_authorized(contract, provider_name):
        raise PermissionError("provider capability is not authorized by contract")
    if "external_effect" not in contract["allowed_effects"]:
        raise PermissionError("external effect is not authorized by contract")

    dispatched = retry_dispatch(aios_dir, effect["effect_id"], actor, attempt_id, provider_name, attempt, retry_authorization=retry_auth)
    _submit_runtime(durable_runtime, "retry", dispatched, attempt_id, provider_name, attempt=attempt)
    return execute_attempt(aios_dir, contract, dispatched, actor, adapter, attempt_id)


def reconcile_unknown_attempt(aios_dir, effect_id, actor, adapter):
    """Ask the provider whether the current UNKNOWN attempt took effect.

    Never re-executes the provider operation. A probe that raises, returns a
    malformed report, or cannot bind its answer to the exact attempt leaves the
    effect UNKNOWN and records nothing (retry remains blocked).
    """
    _text(actor, "actor")
    effect = _load_current(aios_dir, effect_id)
    # Authorize before the probe: a caller that does not own the effect must
    # not be able to trigger provider status queries (PR #126 @18ec11f).
    if effect.get("actor") != actor:
        raise PermissionError("reconciliation actor does not match effect owner")
    if effect.get("state") != "UNKNOWN":
        raise RuntimeError("reconciliation requires an UNKNOWN effect")
    provider_name = _text(getattr(adapter, "name", None), "adapter.name")
    if provider_name != effect.get("provider"):
        raise PermissionError("reconciliation adapter is not the dispatched provider")
    probe = getattr(adapter, "reconcile", None)
    if not callable(probe):
        return {"verdict": "INCONCLUSIVE", "recorded": False, "reason": "provider has no reconciliation probe"}
    try:
        report = probe(effect=dict(effect), attempt_id=effect["attempt_id"])
        if not isinstance(report, ReconciliationReport):
            raise ValueError("provider must return ReconciliationReport")
        if report.verdict == "APPLIED":
            validate_receipt(report.receipt, effect, effect["attempt_id"], provider_name)
            return reconcile_effect(aios_dir, effect_id, actor, "APPLIED", report.evidence,
                                    outcome=report.receipt.outcome,
                                    provider_observation=_provider_observation(report.receipt),
                                    attestation=report.attestation)
        if report.receipt is not None:
            raise ValueError("only APPLIED reconciliation may carry a receipt")
        return reconcile_effect(aios_dir, effect_id, actor, report.verdict, report.evidence,
                                attestation=report.attestation)
    except Exception as exc:  # fail closed: stay UNKNOWN
        return {"verdict": "INCONCLUSIVE", "recorded": False,
                "reason": f"reconciliation probe failed: {type(exc).__name__}: {exc}"}


def execute(aios_dir, contract_id, permit_id, logical_operation_id, actor, adapter,
            durable_runtime: DurableRuntime | None = None):
    """Authorize/create/dispatch the first attempt, then delegate execution."""
    _text(logical_operation_id, "logical_operation_id")
    _text(actor, "actor")
    if not hasattr(adapter, "name"):
        raise ValueError("adapter must expose a provider name")
    provider_name = _text(adapter.name, "adapter.name")

    authorize(aios_dir, contract_id, permit_id)
    contract = load_contract(aios_dir, contract_id)
    permit = load_permit(aios_dir, permit_id)
    if permit["actor"] != actor or contract["actor"] != actor:
        raise PermissionError("actor does not match authorized contract")
    if not _provider_authorized(contract, provider_name):
        raise PermissionError("provider capability is not authorized by contract")
    if "external_effect" not in contract["allowed_effects"]:
        raise PermissionError("external effect is not authorized by contract")

    effect = create_effect(
        aios_dir, contract_id, logical_operation_id, actor, permit_id, "external_effect"
    )
    if effect["state"] != "PLANNED":
        raise RuntimeError("logical operation already has a non-planned effect")
    attempt_id = f"{effect['effect_id']}:attempt:1"
    effect = dispatch(aios_dir, effect["effect_id"], actor, attempt_id, provider_name)
    _submit_runtime(durable_runtime, "submit", effect, attempt_id, provider_name)
    return execute_attempt(aios_dir, contract, effect, actor, adapter, attempt_id)


__all__ = [
    "ProviderReceipt", "ProviderAdapter", "ReconciliationReport", "validate_receipt",
    "reconcile_unknown_attempt", "recover_interrupted",
    "execute_attempt", "resume_attempt", "execute_retry_attempt", "execute",
]
