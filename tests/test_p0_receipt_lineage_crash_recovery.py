# AIOS-CONTRACT: P0 execution integrity — receipt lineage and reconcile-before-retry
# AIOS-REGRESSION: Missing receipts never become success; ambiguous effects are never retried without
#                  a persisted provider-evidenced NOT_APPLIED reconciliation; evaluations bind to the
#                  exact (effect_id, attempt_id, receipt_id) triple.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Crash before provider call, crash after provider success before receipt persistence,
#                    timeout/ambiguous response, forged/tampered lineage. Real provider status APIs and
#                    multi-process crashes are NOT covered (simulated in-process).
# AIOS-BASELINE: 17438b6 (469 passed, 1 skipped)

import json
import os

import pytest

import core.runtime as runtime
from core.effect_authority import (
    dispatch, load_receipt, load_reconciliation, reconcile_effect, recover_interrupted,
    retry_dispatch, transition,
)
from core.evaluation_plane import ExecutionReceipt, evaluate_persisted_receipt, evaluate_receipt
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.runtime import (
    ProviderReceipt, ReconciliationReport, execute, execute_retry_attempt, reconcile_unknown_attempt,
)
from tests.test_m6_runtime import setup_authority

from tests.provider_trust_helpers import sign_observation, sign_reconciliation

ACTOR = "agent:test"
PROVIDER = "fake-provider"


class Crash(BaseException):
    """Simulated process death (not an Exception, so nothing may swallow it)."""


class Provider:
    """Fake provider with an external side-effect ledger and a status API."""

    name = PROVIDER

    def __init__(self, mode="ok"):
        self.mode = mode
        self.applied = {}      # attempt_id -> provider_operation_id
        self.calls = 0
        self.status_answer = None  # override for reconcile(): "APPLIED"/"NOT_APPLIED"/"INCONCLUSIVE"

    def execute(self, *, contract, effect, attempt_id):
        self.calls += 1
        if self.mode == "timeout":
            raise TimeoutError("provider timed out")
        op = f"op-{len(self.applied) + 1}"
        self.applied[attempt_id] = op
        return self._receipt(effect, attempt_id, op)

    def _receipt(self, effect, attempt_id, op):
        # Signs like a real provider holding its trusted key (tests/conftest).
        ev = EvidenceRecord(evidence_id=f"EV-op-{op}", level="OBSERVED",
                            source_ref=f"provider://{self.name}/ops/{op}", claim="provider executed operation",
                            run_id=attempt_id, provider=self.name).as_record()
        observation = {"status": "ok", "op": op, "evidence": ev}
        att = sign_observation(provider=self.name, effect_id=effect["effect_id"], attempt_id=attempt_id,
                               outcome="OBSERVED_SUCCESS", provider_operation_id=op, evidence=ev,
                               observation=observation)
        return ProviderReceipt(provider=self.name, effect_id=effect["effect_id"], attempt_id=attempt_id,
                               provider_operation_id=op, outcome="OBSERVED_SUCCESS",
                               observation=observation, attestation=att)

    def reconcile(self, *, effect, attempt_id):
        verdict = self.status_answer or ("APPLIED" if attempt_id in self.applied else "NOT_APPLIED")
        ev = EvidenceRecord(evidence_id=f"EV-status-{attempt_id[-1]}", level="OBSERVED",
                            source_ref=f"provider://{self.name}/status/{attempt_id}",
                            claim=f"status query verdict {verdict}", run_id=attempt_id,
                            provider=self.name).as_record()
        receipt = self._receipt(effect, attempt_id, self.applied[attempt_id]) if verdict == "APPLIED" else None
        att = sign_reconciliation(effect, verdict, ev, receipt.outcome if receipt else None)
        return ReconciliationReport(verdict=verdict, evidence=ev, receipt=receipt, attestation=att)


def _effect(aios, effect_id):
    with open(os.path.join(aios, "effects", effect_id + ".json"), encoding="utf-8") as fh:
        return json.load(fh)


def _receipts(aios):
    d = os.path.join(aios, "receipts")
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def _explicit(effect_id, attempt):
    return {"mode": "EXPLICIT", "effect_id": effect_id, "attempt": attempt}


# ---------------------------------------------------------------- lineage

def test_success_persists_receipt_bound_to_exact_effect_and_attempt(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    assert done["state"] == "OBSERVED_SUCCESS"
    receipt = load_receipt(aios, done["receipt_id"])
    assert receipt["effect_id"] == done["effect_id"]
    assert receipt["attempt_id"] == f"{done['effect_id']}:attempt:1"
    assert receipt["provider_operation_id"] == "op-1"

    ev = evaluate_persisted_receipt(aios, done["receipt_id"], evaluator_version="e1",
                                    rubric_version="r1", verdict="PASS", result={"ok": True},
                                    timestamp="2026-11-10T00:00:00+00:00")
    assert (ev.effect_id, ev.attempt_id, ev.receipt_id) == (
        done["effect_id"], receipt["attempt_id"], done["receipt_id"])
    assert os.path.exists(os.path.join(aios, "evaluations", ev.evaluation_id + ".json"))
    with pytest.raises(ValueError, match="already recorded"):
        evaluate_persisted_receipt(aios, done["receipt_id"], evaluator_version="e1",
                                   rubric_version="r1", verdict="PASS", result={"ok": True})


def test_unknown_effect_has_no_receipt_and_cannot_be_evaluated(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    eff = execute(aios, cid, pid, "op-1", ACTOR, Provider("timeout"))
    assert eff["state"] == "UNKNOWN"
    assert "receipt_id" not in eff and _receipts(aios) == []
    with pytest.raises(KeyError):
        evaluate_persisted_receipt(aios, "RC-" + "0" * 64, evaluator_version="e1",
                                   rubric_version="r1", verdict="PASS", result={"ok": True})


def test_generic_transition_cannot_mark_success_without_receipt(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    eff = execute(aios, cid, pid, "op-1", ACTOR, Provider("timeout"))
    for target in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        with pytest.raises(TransitionError, match="observe"):
            transition(aios, eff["effect_id"], target, ACTOR, provider_observation={"forged": True})
    assert _effect(aios, eff["effect_id"])["state"] == "UNKNOWN"


def test_tampered_receipt_is_rejected(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    path = os.path.join(aios, "receipts", done["receipt_id"] + ".json")
    rec = json.load(open(path))
    rec["attempt_id"] = rec["attempt_id"].replace(":1", ":9")
    json.dump(rec, open(path, "w"))
    with pytest.raises(TransitionError, match="seal|identity"):
        load_receipt(aios, done["receipt_id"])


def test_evaluation_receipt_id_must_match_receipt():
    r = ExecutionReceipt("EF-1", "EF-1:attempt:1", "OBSERVED", {"EV-1": {"x": 1}}, receipt_id="RC-a")
    with pytest.raises(ValueError, match="receipt_id"):
        evaluate_receipt(r, evaluation_id="E", receipt_id="RC-b", evaluator_version="e", rubric_version="r",
                         verdict="PASS", result={"ok": 1}, evidence_refs=("EV-1",))


# ---------------------------------------------------------------- crash recovery

def test_crash_before_provider_execution_reconciles_then_retries_with_new_attempt(tmp_path, monkeypatch):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=2)
    prov = Provider()

    def die(*a, **k):
        raise Crash()
    with monkeypatch.context() as m:
        m.setattr(runtime, "execute_attempt", die)
        with pytest.raises(Crash):
            execute(aios, cid, pid, "op-1", ACTOR, prov)

    eff_id = next(iter(os.listdir(os.path.join(aios, "effects")))).removesuffix(".json")
    assert _effect(aios, eff_id)["state"] == "DISPATCHED" and prov.calls == 0

    recover_interrupted(aios, eff_id, ACTOR)
    # Ambiguous: retry is blocked until AIOS holds a NOT_APPLIED reconciliation.
    with pytest.raises(TransitionError, match="NOT_APPLIED reconciliation"):
        retry_dispatch(aios, eff_id, ACTOR, f"{eff_id}:attempt:2", PROVIDER, 2, _explicit(eff_id, 2))

    rec = reconcile_unknown_attempt(aios, eff_id, ACTOR, prov)
    assert rec["verdict"] == "NOT_APPLIED"
    eff = _effect(aios, eff_id)
    eff["retry_authorization"] = _explicit(eff_id, 2)
    done = execute_retry_attempt(aios, cid, pid, eff, ACTOR, prov, f"{eff_id}:attempt:2", 2)
    assert done["state"] == "OBSERVED_SUCCESS"
    assert load_receipt(aios, done["receipt_id"])["attempt_id"] == f"{eff_id}:attempt:2"
    assert prov.calls == 1 and len(prov.applied) == 1


def test_provider_success_then_crash_before_receipt_is_reconciled_without_retry(tmp_path, monkeypatch):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    prov = Provider()

    def die(*a, **k):
        raise Crash()
    with monkeypatch.context() as m:
        m.setattr(runtime, "_observe_invoked", die)  # provider already applied; persistence dies
        with pytest.raises(Crash):
            execute(aios, cid, pid, "op-1", ACTOR, prov)

    eff_id = next(iter(os.listdir(os.path.join(aios, "effects")))).removesuffix(".json")
    assert _effect(aios, eff_id)["state"] == "DISPATCHED"
    assert _receipts(aios) == []           # missing receipt ...
    assert prov.calls == 1                 # ... although the external effect happened

    recover_interrupted(aios, eff_id, ACTOR)
    done = reconcile_unknown_attempt(aios, eff_id, ACTOR, prov)
    assert done["state"] == "OBSERVED_SUCCESS"
    receipt = load_receipt(aios, done["receipt_id"])
    assert receipt["recorded_via"] == "reconciliation"
    assert receipt["attempt_id"] == f"{eff_id}:attempt:1"
    # Never re-applied, and no further retry is possible.
    assert prov.calls == 1
    with pytest.raises(TransitionError):
        retry_dispatch(aios, eff_id, ACTOR, f"{eff_id}:attempt:2", PROVIDER, 2, _explicit(eff_id, 2))


def test_timeout_with_inconclusive_status_stays_blocked(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    prov = Provider("timeout")
    eff = execute(aios, cid, pid, "op-1", ACTOR, prov)
    assert eff["state"] == "UNKNOWN"
    prov.status_answer = "INCONCLUSIVE"
    rec = reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, prov)
    assert rec["verdict"] == "INCONCLUSIVE"
    # Negative evidence is persisted, effect stays UNKNOWN, retry stays blocked.
    assert load_reconciliation(aios, eff["effect_id"], 1)["verdict"] == "INCONCLUSIVE"
    assert _effect(aios, eff["effect_id"])["state"] == "UNKNOWN"
    with pytest.raises(TransitionError, match="NOT_APPLIED"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", PROVIDER, 2,
                       _explicit(eff["effect_id"], 2))
    # A later decisive answer may supersede INCONCLUSIVE.
    prov.status_answer = "NOT_APPLIED"
    assert reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, prov)["verdict"] == "NOT_APPLIED"


def test_failing_probe_records_nothing_and_blocks_retry(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=2)
    prov = Provider("timeout")
    eff = execute(aios, cid, pid, "op-1", ACTOR, prov)

    def broken(**kw):
        raise ConnectionError("status API down")
    prov.reconcile = broken
    out = reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, prov)
    assert out == {"verdict": "INCONCLUSIVE", "recorded": False,
                   "reason": "reconciliation probe failed: ConnectionError: status API down"}
    assert load_reconciliation(aios, eff["effect_id"], 1) is None


# ---------------------------------------------------------------- adversarial

def test_reconciliation_evidence_must_bind_to_unknown_attempt(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=2)
    eff = execute(aios, cid, pid, "op-1", ACTOR, Provider("timeout"))
    wrong_run = EvidenceRecord("EV-x", "OBSERVED", "provider://fake-provider/status", "not applied",
                               f"{eff['effect_id']}:attempt:7", PROVIDER).as_record()
    with pytest.raises(ValueError, match="bound to the UNKNOWN attempt"):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", wrong_run)
    wrong_provider = EvidenceRecord("EV-y", "OBSERVED", "provider://other/status", "not applied",
                                    eff["attempt_id"], "other-provider").as_record()
    with pytest.raises(ValueError, match="provider"):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", wrong_provider)
    forged = EvidenceRecord("EV-z", "OBSERVED", "provider://fake-provider/status", "not applied",
                            eff["attempt_id"], PROVIDER).as_record()
    forged["digest"] = "0" * 64
    with pytest.raises(ValueError, match="valid AIOS evidence"):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", forged)
    with pytest.raises(TransitionError, match="owner"):
        reconcile_effect(aios, eff["effect_id"], "agent:intruder", "NOT_APPLIED", forged)


def test_wrong_provider_cannot_reconcile(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=2)
    eff = execute(aios, cid, pid, "op-1", ACTOR, Provider("timeout"))

    class Other(Provider):
        name = "other-provider"
    with pytest.raises(PermissionError):
        reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, Other())


def test_not_applied_for_previous_attempt_does_not_authorize_later_retry(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    prov = Provider("timeout")
    eff = execute(aios, cid, pid, "op-1", ACTOR, prov)
    eid = eff["effect_id"]
    assert reconcile_unknown_attempt(aios, eid, ACTOR, prov)["verdict"] == "NOT_APPLIED"
    eff = _effect(aios, eid)
    eff["retry_authorization"] = _explicit(eid, 2)
    second = execute_retry_attempt(aios, cid, pid, eff, ACTOR, prov, f"{eid}:attempt:2", 2)
    assert second["state"] == "UNKNOWN" and second["attempt"] == 2
    # Attempt-1 reconciliation must not unlock attempt 3.
    with pytest.raises(TransitionError, match="NOT_APPLIED reconciliation"):
        retry_dispatch(aios, eid, ACTOR, f"{eid}:attempt:3", PROVIDER, 3, _explicit(eid, 3))


def test_decisive_reconciliation_cannot_be_rewritten(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=2)
    prov = Provider("timeout")
    eff = execute(aios, cid, pid, "op-1", ACTOR, prov)
    assert reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, prov)["verdict"] == "NOT_APPLIED"
    ev = EvidenceRecord("EV-2", "OBSERVED", "provider://fake-provider/status", "inconclusive",
                        eff["attempt_id"], PROVIDER).as_record()
    with pytest.raises(TransitionError, match="decisive"):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "INCONCLUSIVE", ev)


def test_applied_reconciliation_requires_matching_receipt(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=2)
    prov = Provider("timeout")
    eff = execute(aios, cid, pid, "op-1", ACTOR, prov)
    prov.status_answer = "APPLIED"
    prov.applied[eff["attempt_id"]] = "op-x"
    real = prov.reconcile

    def wrong_attempt(**kw):
        report = real(**kw)
        bad = ProviderReceipt(PROVIDER, eff["effect_id"], eff["effect_id"] + ":attempt:2", "op-x",
                              "OBSERVED_SUCCESS", {"status": "ok"})
        return ReconciliationReport("APPLIED", report.evidence, bad)
    prov.reconcile = wrong_attempt
    out = reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, prov)
    assert out["recorded"] is False
    assert _effect(aios, eff["effect_id"])["state"] == "UNKNOWN" and _receipts(aios) == []


def test_duplicate_observation_of_same_attempt_is_rejected(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    with pytest.raises(TransitionError):
        runtime._observe_invoked(aios, done["effect_id"], ACTOR, "OBSERVED_SUCCESS", done["provider_observation"])


def test_retry_reconciliation_cas_uses_exact_validated_snapshot(tmp_path, monkeypatch):
    """A replacement after validation must fail CAS, never authorize retry."""
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=2)
    prov = Provider("timeout")
    eff = execute(aios, cid, pid, "op-race", ACTOR, prov)
    eid = eff["effect_id"]
    assert reconcile_unknown_attempt(aios, eid, ACTOR, prov)["verdict"] == "NOT_APPLIED"
    rel = os.path.join(aios, "reconciliations", f"{eid}-attempt-1.json")
    with open(rel, encoding="utf-8") as fh:
        original = json.load(fh)

    import core.effect_authority as authority
    real_loader = authority._load_reconciliation_cas

    def swap_after_snapshot(*args, **kwargs):
        record, digest = real_loader(*args, **kwargs)
        tampered = dict(original)
        tampered["actor"] = "attacker"
        with open(rel, "w", encoding="utf-8") as fh:
            json.dump(tampered, fh)
        return record, digest

    monkeypatch.setattr(authority, "_load_reconciliation_cas", swap_after_snapshot)
    with pytest.raises(TransitionError):
        retry_dispatch(aios, eid, ACTOR, f"{eid}:attempt:2", PROVIDER, 2, _explicit(eid, 2))
    assert _effect(aios, eid)["state"] == "UNKNOWN"
    assert prov.calls == 1


def test_reconcile_effect_cas_uses_exact_validated_snapshot(tmp_path, monkeypatch):
    """A replacement after validating prior INCONCLUSIVE evidence must fail CAS."""
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=2)
    prov = Provider("timeout")
    eff = execute(aios, cid, pid, "op-reconcile-race", ACTOR, prov)
    eid = eff["effect_id"]

    prov.status_answer = "INCONCLUSIVE"
    first = reconcile_unknown_attempt(aios, eid, ACTOR, prov)
    assert first["verdict"] == "INCONCLUSIVE"

    rel = os.path.join(aios, "reconciliations", f"{eid}-attempt-1.json")
    with open(rel, encoding="utf-8") as fh:
        original = json.load(fh)

    import core.effect_authority as authority
    real_loader = authority._load_reconciliation_cas

    def swap_after_snapshot(*args, **kwargs):
        record, digest = real_loader(*args, **kwargs)
        tampered = dict(original)
        tampered["actor"] = "attacker"
        with open(rel, "w", encoding="utf-8") as fh:
            json.dump(tampered, fh)
        return record, digest

    monkeypatch.setattr(authority, "_load_reconciliation_cas", swap_after_snapshot)
    prov.status_answer = "NOT_APPLIED"
    result = reconcile_unknown_attempt(aios, eid, ACTOR, prov)
    assert result["recorded"] is False
    assert "compare-and-swap" in result["reason"]
    assert _effect(aios, eid)["state"] == "UNKNOWN"
    assert prov.calls == 1
