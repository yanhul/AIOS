# AIOS-CONTRACT: An OBSERVED_* effect exists only together with a receipt of record that carries a valid AIOS
#                deployment seal (PR #126 @74017b7 P0, receipt sealing fail-open).
# AIOS-REGRESSION: With AIOS_RECORD_SEAL_SECRET absent, invalid, or producing an unverifiable seal at the moment
#                  the receipt is written, a provider-signed observation (observe(), AIOS-invoked execution or an
#                  APPLIED reconciliation) must raise SealError and persist nothing: no receipt, no OBSERVED_*
#                  effect, no reconciliation, no observe event. The pre-fix code silently wrote
#                  {"sealed": false} receipts while moving the effect to OBSERVED_*. A planted OBSERVED_* effect
#                  without a sealed receipt of record is refused by the validated effect loader. Recovery after
#                  the refused write stays non-final and goes through reconciliation; nothing is retried.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: The key vanishing mid-operation is simulated in-process (env change between authority
#                    validation and receipt sealing). Planted pending-journal batches are covered only through
#                    the loader invariant they would roll forward into. A process holding the seal secret can
#                    still forge (record_seal threat model).
# AIOS-BASELINE: 74017b7 (608 passed, 1 skipped)

import json
import os

import pytest

import core.effect_authority as ea
import core.runtime as runtime
from core.effect_authority import (
    create_effect, dispatch, load_receipt, observe, receipt_id_for, reconcile_effect, recover_interrupted,
    retry_dispatch,
)
from core.evaluation_plane import evaluate_persisted_receipt
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.record_seal import SEAL_ENV, SealError, require_seal, seal, seal_available, unsealed_body
from core.runtime import execute, reconcile_unknown_attempt, resume_attempt
from tests.provider_trust_helpers import sign_observation, sign_reconciliation
from tests.test_m6_runtime import setup_authority
from tests.test_p0_receipt_lineage_crash_recovery import ACTOR, PROVIDER, Provider

TEST_KEY = "aios-test-only-seal-secret"  # tests/conftest


# ------------------------------------------------------------------ helpers

def _raw_effect(aios, eid):
    with open(os.path.join(aios, "effects", eid + ".json"), encoding="utf-8") as fh:
        return json.load(fh)


def _listing(aios, sub):
    d = os.path.join(aios, sub)
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def _observe_events(aios, eid):
    return [f for f in _listing(aios, "events") if f.startswith(f"effect-{eid}-OBSERVED_")]


def _dispatched(tmp_path, max_attempts=3):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=max_attempts)
    eff = create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    eid = eff["effect_id"]
    return aios, cid, pid, dispatch(aios, eid, ACTOR, f"{eid}:attempt:1", PROVIDER)


def _signed_observation(eff, op="op-1", outcome="OBSERVED_SUCCESS"):
    """A genuine, provider-signed observation for the dispatched attempt (passes every trust check)."""
    ev = EvidenceRecord(f"EV-{op}", "OBSERVED", f"provider://{PROVIDER}/ops/{op}", "provider executed operation",
                        eff["attempt_id"], PROVIDER).as_record()
    obs = {"status": "ok"}
    att = sign_observation(provider=PROVIDER, effect_id=eff["effect_id"], attempt_id=eff["attempt_id"],
                           outcome=outcome, provider_operation_id=op, evidence=ev, observation=obs)
    return {"attempt_id": eff["attempt_id"], "provider": PROVIDER, "provider_operation_id": op,
            "effect_id": eff["effect_id"], "evidence": ev, "observation": obs, "attestation": att}


def _key_changes_before_receipt_seal(monkeypatch, new_value):
    """Change the deployment key *after* authority validation, right before the receipt is built.

    Authority validation (sealed capability registry, execution claim, reconciliation record) needs the key,
    so a key that is absent from the start is already refused at entry. This hook reaches the receipt writer
    itself -- the code that used to downgrade to an unsealed receipt.
    """
    original = ea._validated_observation

    def hook(*args, **kwargs):
        if new_value is None:
            monkeypatch.delenv(SEAL_ENV, raising=False)
        else:
            monkeypatch.setenv(SEAL_ENV, new_value)
        return original(*args, **kwargs)
    monkeypatch.setattr(ea, "_validated_observation", hook)


def _assert_nothing_observed(aios, eff, state="DISPATCHED"):
    eid = eff["effect_id"]
    raw = _raw_effect(aios, eid)
    assert raw["state"] == state
    assert "receipt_id" not in raw and "provider_observation" not in raw
    assert _listing(aios, "receipts") == []
    assert _observe_events(aios, eid) == []


# ------------------------------------------------------------------ observe(): missing / invalid key

def test_observe_refuses_signed_observation_when_seal_key_disappears(tmp_path, monkeypatch):
    aios, _, _, eff = _dispatched(tmp_path)
    _key_changes_before_receipt_seal(monkeypatch, None)
    with pytest.raises(SealError, match="not configured"):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _signed_observation(eff))
    _assert_nothing_observed(aios, eff)


@pytest.mark.parametrize("outcome", ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"])
def test_no_observed_transition_of_either_outcome_without_sealed_receipt(tmp_path, monkeypatch, outcome):
    aios, _, _, eff = _dispatched(tmp_path)
    _key_changes_before_receipt_seal(monkeypatch, None)
    with pytest.raises(SealError):
        observe(aios, eff["effect_id"], ACTOR, outcome, _signed_observation(eff, outcome=outcome))
    _assert_nothing_observed(aios, eff)


def test_observe_with_seal_key_absent_from_the_start_fails_closed(tmp_path, monkeypatch):
    aios, _, _, eff = _dispatched(tmp_path)
    monkeypatch.delenv(SEAL_ENV)
    with pytest.raises(TransitionError, match="not configured"):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _signed_observation(eff))
    monkeypatch.setenv(SEAL_ENV, TEST_KEY)
    _assert_nothing_observed(aios, eff)


@pytest.mark.parametrize("invalid", ["   ", "\t\n", "\r\n"])
def test_whitespace_only_seal_key_is_invalid_configuration(monkeypatch, invalid):
    monkeypatch.setenv(SEAL_ENV, invalid)
    assert seal_available() is False
    with pytest.raises(SealError, match="invalid"):
        seal({"record_type": "PROVIDER_RECEIPT", "x": 1})


@pytest.mark.parametrize("invalid", ["   ", "\t\n"])
def test_observe_refuses_when_seal_key_is_invalid_at_write_time(tmp_path, monkeypatch, invalid):
    aios, _, _, eff = _dispatched(tmp_path)
    _key_changes_before_receipt_seal(monkeypatch, invalid)
    with pytest.raises(SealError, match="invalid"):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _signed_observation(eff))
    monkeypatch.setenv(SEAL_ENV, TEST_KEY)
    _assert_nothing_observed(aios, eff)


def test_observe_refuses_a_seal_that_does_not_verify(tmp_path, monkeypatch):
    """A broken sealer / key configuration whose output does not verify must not be persisted."""
    aios, _, _, eff = _dispatched(tmp_path)

    def broken_seal(record):
        sealed = seal(record)
        return {**sealed, "seal": {**sealed["seal"], "mac": "0" * 64}}
    monkeypatch.setattr(ea, "seal", broken_seal)
    with pytest.raises(SealError):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _signed_observation(eff))
    _assert_nothing_observed(aios, eff)


def test_observe_refuses_a_seal_that_is_silently_skipped(tmp_path, monkeypatch):
    aios, _, _, eff = _dispatched(tmp_path)
    monkeypatch.setattr(ea, "seal", lambda record: {**record, "sealed": False})
    with pytest.raises(SealError, match="not sealed"):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _signed_observation(eff))
    _assert_nothing_observed(aios, eff)


# ------------------------------------------------------------------ recovery after the refused write

def test_recovery_after_refused_observe_is_safe_and_resubmission_seals(tmp_path, monkeypatch):
    aios, _, _, eff = _dispatched(tmp_path)
    eid = eff["effect_id"]
    po = _signed_observation(eff)
    with monkeypatch.context() as m:
        _key_changes_before_receipt_seal(m, None)
        with pytest.raises(SealError):
            observe(aios, eid, ACTOR, "OBSERVED_SUCCESS", po)
    monkeypatch.setenv(SEAL_ENV, TEST_KEY)
    # Not final, not retryable: still the same DISPATCHED attempt.
    assert ea._load_current(aios, eid)["state"] == "DISPATCHED"
    with pytest.raises(TransitionError, match="requires UNKNOWN"):
        retry_dispatch(aios, eid, ACTOR, f"{eid}:attempt:2", PROVIDER, 2,
                       {"mode": "EXPLICIT", "effect_id": eid, "attempt": 2})
    # Once the key is back, the same provider-signed observation is recorded with a sealed receipt.
    done = observe(aios, eid, ACTOR, "OBSERVED_SUCCESS", po)
    assert done["state"] == "OBSERVED_SUCCESS"
    receipt = load_receipt(aios, done["receipt_id"], require_provider_signed=True)
    require_seal(receipt, "provider receipt")
    assert "sealed" not in receipt and receipt["attempt_id"] == f"{eid}:attempt:1"


def test_invoked_execution_with_unsealable_receipt_is_reconciled_not_finalized_or_retried(tmp_path, monkeypatch):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    prov = Provider()
    with monkeypatch.context() as m:
        _key_changes_before_receipt_seal(m, None)
        with pytest.raises(SealError):
            execute(aios, cid, pid, "op-1", ACTOR, prov)
    monkeypatch.setenv(SEAL_ENV, TEST_KEY)
    eid = _listing(aios, "effects")[0].removesuffix(".json")
    eff = ea._load_current(aios, eid)
    _assert_nothing_observed(aios, eff)
    assert prov.calls == 1  # the provider did apply the effect

    contract = ea.load_contract(aios, cid)
    done = resume_attempt(aios, contract, eff, ACTOR, prov, None)  # non-idempotent => reconcile, never re-run
    assert done["state"] == "OBSERVED_SUCCESS"
    assert prov.calls == 1
    receipt = load_receipt(aios, done["receipt_id"])
    require_seal(receipt, "provider receipt")
    assert receipt["recorded_via"] == "reconciliation" and receipt["provider"] == PROVIDER


def test_applied_reconciliation_refuses_unsealable_receipt_and_keeps_effect_unknown(tmp_path, monkeypatch):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    prov = Provider("timeout")
    eff = execute(aios, cid, pid, "op-1", ACTOR, prov)
    assert eff["state"] == "UNKNOWN"
    po = _signed_observation(eff)
    ev = EvidenceRecord("EV-status", "OBSERVED", f"provider://{PROVIDER}/status/1", "status APPLIED",
                        eff["attempt_id"], PROVIDER).as_record()
    att = sign_reconciliation(eff, "APPLIED", ev, "OBSERVED_SUCCESS")
    with monkeypatch.context() as m:
        _key_changes_before_receipt_seal(m, None)
        with pytest.raises(SealError):
            reconcile_effect(aios, eff["effect_id"], ACTOR, "APPLIED", ev, outcome="OBSERVED_SUCCESS",
                             provider_observation=po, attestation=att)
    monkeypatch.setenv(SEAL_ENV, TEST_KEY)
    _assert_nothing_observed(aios, eff, state="UNKNOWN")
    assert _listing(aios, "reconciliations") == []
    # Still blocked for retry: no NOT_APPLIED was recorded.
    with pytest.raises(TransitionError, match="NOT_APPLIED"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", PROVIDER, 2,
                       {"mode": "EXPLICIT", "effect_id": eff["effect_id"], "attempt": 2})
    done = reconcile_effect(aios, eff["effect_id"], ACTOR, "APPLIED", ev, outcome="OBSERVED_SUCCESS",
                            provider_observation=po, attestation=att)
    require_seal(load_receipt(aios, done["receipt_id"]), "provider receipt")


def test_probe_path_with_missing_key_records_nothing(tmp_path, monkeypatch):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    prov = Provider()
    with monkeypatch.context() as m:
        m.setattr(runtime, "_observe_invoked", lambda *a, **k: (_ for _ in ()).throw(SystemExit(137)))
        with pytest.raises(SystemExit):
            execute(aios, cid, pid, "op-1", ACTOR, prov)
    eid = _listing(aios, "effects")[0].removesuffix(".json")
    recover_interrupted(aios, eid, ACTOR)
    _key_changes_before_receipt_seal(monkeypatch, None)
    out = reconcile_unknown_attempt(aios, eid, ACTOR, prov)
    monkeypatch.setenv(SEAL_ENV, TEST_KEY)
    assert out["recorded"] is False and out["verdict"] == "INCONCLUSIVE"
    eff = ea._load_current(aios, eid)
    _assert_nothing_observed(aios, eff, state="UNKNOWN")
    assert _listing(aios, "reconciliations") == []


# ------------------------------------------------------------------ planted state: loader invariant

def _done(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    assert done["state"] == "OBSERVED_SUCCESS"
    return aios, done


def _write_effect(aios, eff):
    with open(os.path.join(aios, "effects", eff["effect_id"] + ".json"), "w", encoding="utf-8") as fh:
        json.dump(eff, fh)


def _downgrade_receipt_to_unsealed(aios, done):
    """What the pre-fix writer produced: same content address, {"sealed": false}, no seal."""
    path = os.path.join(aios, "receipts", done["receipt_id"] + ".json")
    body = {k: v for k, v in unsealed_body(json.load(open(path))).items()}
    assert receipt_id_for(body) == done["receipt_id"]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({**body, "sealed": False}, fh)


def test_unsealed_receipt_of_record_is_not_authoritative_even_when_seal_check_is_opted_out(tmp_path):
    aios, done = _done(tmp_path)
    _downgrade_receipt_to_unsealed(aios, done)
    for kwargs in ({}, {"require_sealed": False}):
        with pytest.raises(SealError):
            load_receipt(aios, done["receipt_id"], **kwargs)
    with pytest.raises(SealError):
        ea._load_current(aios, done["effect_id"])
    with pytest.raises(SealError):
        evaluate_persisted_receipt(aios, done["receipt_id"], evaluator_version="e1", rubric_version="r1",
                                   verdict="PASS", result={"ok": True})
    assert _listing(aios, "evaluations") == []


@pytest.mark.parametrize("state", ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"])
def test_planted_observed_effect_without_receipt_is_refused_by_the_loader(tmp_path, state):
    aios, _, _, eff = _dispatched(tmp_path)
    raw = _raw_effect(aios, eff["effect_id"])
    _write_effect(aios, {**raw, "state": state, "provider_observation": _signed_observation(eff)})
    with pytest.raises(TransitionError, match="receipt"):
        ea._load_current(aios, eff["effect_id"])
    _write_effect(aios, {**raw, "state": state, "receipt_id": "RC-" + "a" * 64})
    with pytest.raises(TransitionError, match="receipt"):
        ea._load_current(aios, eff["effect_id"])


def test_observed_effect_cannot_borrow_another_effects_sealed_receipt(tmp_path):
    aios, done = _done(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    other = create_effect(aios, cid, "op-2", ACTOR, pid, "external_effect")
    other = dispatch(aios, other["effect_id"], ACTOR, f"{other['effect_id']}:attempt:1", PROVIDER)
    _write_effect(aios, {**other, "state": "OBSERVED_SUCCESS", "receipt_id": done["receipt_id"]})
    with pytest.raises(TransitionError, match="receipt"):
        ea._load_current(aios, other["effect_id"])


def test_observed_effect_with_outcome_differing_from_sealed_receipt_is_refused(tmp_path):
    aios, done = _done(tmp_path)
    _write_effect(aios, {**_raw_effect(aios, done["effect_id"]), "state": "OBSERVED_FAILURE"})
    with pytest.raises(TransitionError, match="receipt"):
        ea._load_current(aios, done["effect_id"])


# ------------------------------------------------------------------ valid sealed flow still works

def test_valid_sealed_receipt_flow_is_unchanged(tmp_path):
    aios, done = _done(tmp_path)
    receipt = load_receipt(aios, done["receipt_id"], require_provider_signed=True)
    require_seal(receipt, "provider receipt")
    assert "sealed" not in receipt
    assert ea._load_current(aios, done["effect_id"])["receipt_id"] == done["receipt_id"]
    ev = evaluate_persisted_receipt(aios, done["receipt_id"], evaluator_version="e1", rubric_version="r1",
                                    verdict="PASS", result={"ok": True}, timestamp="2026-11-10T00:00:00+00:00")
    assert ev.receipt_id == done["receipt_id"]
