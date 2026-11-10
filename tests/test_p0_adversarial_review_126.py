# AIOS-CONTRACT: P0 external-effect authority under adversarial review (PR #126 review F1–F9)
# AIOS-REGRESSION: Forged/edited authority JSON, racing processes, non-idempotent resume, unbound
#                  evidence, provider substitution and mid-batch process death must all fail closed.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Seals defend against writers without the deployment secret only; provider
#                    authenticity (provider-signed responses) is NOT covered. Races are forced with
#                    real forked processes + barriers on Linux (fcntl); Windows locking not exercised.
# AIOS-BASELINE: e6c2aed (484 passed, 1 skipped)

import json
import multiprocessing as mp
import os

import pytest

import core.effect_authority as ea
import core.mutation as mutation
import core.runtime as runtime
from core.effect_authority import (
    dispatch, load_receipt, observe, receipt_id_for, reconcile_effect, recover_interrupted,
    retry_dispatch,
)
from core.evaluation_plane import evaluate_persisted_receipt
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.record_seal import SEAL_ENV, SealError, unsealed_body
from core.runtime import ProviderReceipt, ReconciliationReport, execute, resume_attempt
from tests.test_m6_runtime import setup_authority
from tests.test_p0_receipt_lineage_crash_recovery import ACTOR, PROVIDER, Provider

pytestmark = pytest.mark.skipif(os.name != "posix", reason="uses fork + os._exit process tests")
CTX = mp.get_context("fork")


def _effect(aios, eid):
    return json.load(open(os.path.join(aios, "effects", eid + ".json")))


def _only_effect_id(aios):
    (name,) = os.listdir(os.path.join(aios, "effects"))
    return name.removesuffix(".json")


def _explicit(eid, attempt):
    return {"mode": "EXPLICIT", "effect_id": eid, "attempt": attempt}


def _status_evidence(effect, claim="not applied"):
    return EvidenceRecord(f"EV-st-{effect['attempt']}", "OBSERVED", f"provider://{effect['provider']}/status",
                          claim, effect["attempt_id"], effect["provider"]).as_record()


def _unknown_effect(tmp_path, max_attempts=3):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=max_attempts)
    eff = execute(aios, cid, pid, "op-1", ACTOR, Provider("timeout"))
    assert eff["state"] == "UNKNOWN"
    return aios, cid, pid, eff


class FileProvider(Provider):
    """Provider whose side-effect ledger lives on disk so it survives process death."""

    def __init__(self, ledger, mode="ok"):
        super().__init__(mode)
        self.ledger = ledger

    def _read(self):
        return json.load(open(self.ledger)) if os.path.exists(self.ledger) else {}

    def execute(self, *, contract, effect, attempt_id):
        led = self._read()
        op = f"op-{len(led) + 1}"
        led[attempt_id] = op
        json.dump(led, open(self.ledger, "w"))
        return self._receipt(effect, attempt_id, op)

    def reconcile(self, *, effect, attempt_id):
        self.applied = self._read()
        return super().reconcile(effect=effect, attempt_id=attempt_id)


# ------------------------------------------------------------------ F1: forged reconciliation JSON

def _forge_reconciliation(aios, eff, seal_stamp=None):
    rec = {"record_type": "EFFECT_RECONCILIATION", "effect_id": eff["effect_id"], "attempt": 1,
           "attempt_id": eff["attempt_id"], "contract_id": eff["contract_id"], "provider": eff["provider"],
           "verdict": "NOT_APPLIED", "evidence": _status_evidence(eff), "actor": ACTOR, "supersedes": None}
    if seal_stamp is not None:
        rec["seal"] = seal_stamp
    d = os.path.join(aios, "reconciliations")
    os.makedirs(d, exist_ok=True)
    json.dump(rec, open(os.path.join(d, f"{eff['effect_id']}-attempt-1.json"), "w"))


def test_f1_forged_unsealed_reconciliation_with_valid_evidence_digest_cannot_unlock_retry(tmp_path):
    aios, _, _, eff = _unknown_effect(tmp_path)
    _forge_reconciliation(aios, eff)  # evidence digest is valid; no AIOS seal
    with pytest.raises(SealError, match="not sealed"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", PROVIDER, 2,
                       _explicit(eff["effect_id"], 2))
    assert _effect(aios, eff["effect_id"])["state"] == "UNKNOWN"


def test_f1_reconciliation_sealed_with_another_key_is_rejected(tmp_path, monkeypatch):
    aios, _, _, eff = _unknown_effect(tmp_path)
    monkeypatch.setenv(SEAL_ENV, "attacker-key")
    reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", _status_evidence(eff))
    monkeypatch.setenv(SEAL_ENV, "aios-test-only-seal-secret")
    with pytest.raises(SealError, match="different key"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", PROVIDER, 2,
                       _explicit(eff["effect_id"], 2))


def test_f1_edited_sealed_reconciliation_is_rejected(tmp_path):
    aios, _, _, eff = _unknown_effect(tmp_path)
    reconcile_effect(aios, eff["effect_id"], ACTOR, "INCONCLUSIVE", _status_evidence(eff, "inconclusive"))
    path = os.path.join(aios, "reconciliations", f"{eff['effect_id']}-attempt-1.json")
    rec = json.load(open(path))
    rec["verdict"] = "NOT_APPLIED"
    json.dump(rec, open(path, "w"))
    with pytest.raises(SealError, match="does not match"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", PROVIDER, 2,
                       _explicit(eff["effect_id"], 2))


def test_f1_without_seal_key_reconciliation_and_retry_fail_closed(tmp_path, monkeypatch):
    aios, _, _, eff = _unknown_effect(tmp_path)
    monkeypatch.delenv(SEAL_ENV)
    with pytest.raises(SealError, match="not configured"):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", _status_evidence(eff))
    assert not os.path.exists(os.path.join(aios, "reconciliations", f"{eff['effect_id']}-attempt-1.json"))


# ------------------------------------------------------------------ F2: racing processes

def _race(aios, n, target, patch_name):
    """Run ``target`` in n forked processes that all read state before any of them writes."""
    barrier = CTX.Barrier(n)
    results = CTX.Queue()

    def child(i):
        orig = getattr(ea, patch_name)

        def synced(*a, **k):
            out = orig(*a, **k)
            barrier.wait(timeout=20)  # every process has read the same pre-state
            return out
        setattr(ea, patch_name, synced)
        try:
            target(i)
            results.put(("ok", i))
        except Exception as exc:  # noqa: BLE001 - reported to parent
            results.put(("err", f"{type(exc).__name__}: {exc}"))

    procs = [CTX.Process(target=child, args=(i,)) for i in range(n)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    return [results.get(timeout=5) for _ in procs]


def test_f2_two_processes_cannot_both_dispatch_the_same_retry(tmp_path):
    aios, cid, pid, eff = _unknown_effect(tmp_path)
    reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", _status_evidence(eff))
    eid = eff["effect_id"]
    out = _race(aios, 2, lambda i: retry_dispatch(aios, eid, ACTOR, f"{eid}:attempt:2", PROVIDER, 2,
                                                  _explicit(eid, 2)), "_load_current_cas")
    oks = [r for r in out if r[0] == "ok"]
    errs = [r[1] for r in out if r[0] == "err"]
    assert len(oks) == 1, out
    assert len(errs) == 1 and "compare-and-swap" in errs[0], out
    assert _effect(aios, eid)["attempt"] == 2


def test_f2_two_processes_cannot_both_dispatch_initial_attempt(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    eff = ea.create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    eid = eff["effect_id"]
    out = _race(aios, 2, lambda i: dispatch(aios, eid, ACTOR, f"{eid}:attempt:1", PROVIDER), "_load_current_cas")
    assert sorted(r[0] for r in out) == ["err", "ok"], out


def test_f2_two_processes_cannot_both_observe(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    eff = ea.create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    eid = eff["effect_id"]
    eff = dispatch(aios, eid, ACTOR, f"{eid}:attempt:1", PROVIDER)

    def obs(i):
        ev = EvidenceRecord(f"EV-{i}", "OBSERVED", "provider://x", "done", eff["attempt_id"], PROVIDER).as_record()
        observe(aios, eid, ACTOR, "OBSERVED_SUCCESS" if i == 0 else "OBSERVED_FAILURE",
                {"attempt_id": eff["attempt_id"], "provider": PROVIDER, "provider_operation_id": f"op-{i}",
                 "evidence": ev})
    out = _race(aios, 2, obs, "_load_current_cas")
    assert sorted(r[0] for r in out) == ["err", "ok"], out
    assert len(os.listdir(os.path.join(aios, "receipts"))) == 1
    final = _effect(aios, eid)
    assert load_receipt(aios, final["receipt_id"])["outcome"] == final["state"]


# ------------------------------------------------------------------ F3: resume must not double-apply

def test_f3_resume_after_provider_applied_does_not_reexecute_non_idempotent_provider(tmp_path):
    aios = str(tmp_path)
    c, cid, pid = setup_authority(tmp_path, max_attempts=2)
    ledger = str(tmp_path / "ledger.json")

    def run_and_die():
        prov = FileProvider(ledger)
        runtime.observe = lambda *a, **k: os._exit(137)  # applied, then process dies
        execute(aios, cid, pid, "op-1", ACTOR, prov)
    p = CTX.Process(target=run_and_die)
    p.start()
    p.join(30)
    assert p.exitcode == 137

    eid = _only_effect_id(aios)
    assert _effect(aios, eid)["state"] == "DISPATCHED"
    assert len(json.load(open(ledger))) == 1
    prov = FileProvider(ledger)
    contract = __import__("core.authority", fromlist=["load_contract"]).load_contract(aios, cid)
    done = resume_attempt(aios, contract, _effect(aios, eid), ACTOR, prov, None)
    assert done["state"] == "OBSERVED_SUCCESS"
    assert load_receipt(aios, done["receipt_id"])["recorded_via"] == "reconciliation"
    assert len(json.load(open(ledger))) == 1  # never applied twice


# ------------------------------------------------------------------ F4: evidence must bind to attempt

def _dispatched(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    eff = ea.create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    return aios, dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:1", PROVIDER)


def test_f4_observe_rejects_evidence_for_another_run(tmp_path):
    aios, eff = _dispatched(tmp_path)
    ev = EvidenceRecord("EV-1", "OBSERVED", "provider://x", "done", "some-other-run", PROVIDER).as_record()
    with pytest.raises(ValueError, match="not bound to the dispatched attempt"):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS",
                {"attempt_id": eff["attempt_id"], "provider": PROVIDER, "provider_operation_id": "op",
                 "evidence": ev})


def test_f4_observe_requires_provider_operation_id(tmp_path):
    aios, eff = _dispatched(tmp_path)
    ev = EvidenceRecord("EV-1", "OBSERVED", "provider://x", "done", eff["attempt_id"], PROVIDER).as_record()
    with pytest.raises(ValueError, match="provider_operation_id"):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS",
                {"attempt_id": eff["attempt_id"], "provider": PROVIDER, "evidence": ev})


# ------------------------------------------------------------------ F5: provider substitution

def test_f5_retry_cannot_switch_provider(tmp_path):
    aios, _, _, eff = _unknown_effect(tmp_path)
    reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", _status_evidence(eff))
    with pytest.raises(TransitionError, match="reconciled provider"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", "provider-b", 2,
                       _explicit(eff["effect_id"], 2))


def test_f5_dispatch_requires_contract_capability(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    eff = ea.create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    with pytest.raises(TransitionError, match="capability"):
        dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:1", "unlisted-provider")


# ------------------------------------------------------------------ F6/F7: receipt integrity

@pytest.mark.parametrize("field,value", [("recorded_via", "reconciliation"), ("contract_id", "CT-other"),
                                         ("attempt", 9), ("record_type", "PROVIDER_RECEIPT_X")])
def test_f6_editing_any_receipt_field_is_detected(tmp_path, field, value):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    path = os.path.join(aios, "receipts", done["receipt_id"] + ".json")
    rec = json.load(open(path))
    rec[field] = value
    json.dump(rec, open(path, "w"))
    with pytest.raises(TransitionError):
        load_receipt(aios, done["receipt_id"])


def test_f6_receipt_id_covers_every_field():
    base = {"record_type": "PROVIDER_RECEIPT", "effect_id": "E", "attempt_id": "E:attempt:1", "attempt": 1,
            "contract_id": "C", "provider": "p", "provider_operation_id": "o", "outcome": "OBSERVED_SUCCESS",
            "evidence": {"digest": "d"}, "recorded_via": "observe"}
    ids = {receipt_id_for(base)}
    for k in base:
        changed = dict(base)
        changed[k] = "changed" if k != "attempt" else 2
        ids.add(receipt_id_for(changed))
    assert len(ids) == len(base) + 1


def test_f7_forged_receipt_and_effect_pointer_cannot_be_evaluated(tmp_path):
    aios, _, _, eff = _unknown_effect(tmp_path)
    eid = eff["effect_id"]
    ev = EvidenceRecord("EV-f", "OBSERVED", "provider://x", "forged", eff["attempt_id"], PROVIDER).as_record()
    body = {"record_type": "PROVIDER_RECEIPT", "effect_id": eid, "attempt_id": eff["attempt_id"], "attempt": 1,
            "contract_id": eff["contract_id"], "provider": PROVIDER, "provider_operation_id": "op-f",
            "outcome": "OBSERVED_SUCCESS", "evidence": ev, "recorded_via": "observe"}
    rid = receipt_id_for(body)
    os.makedirs(os.path.join(aios, "receipts"), exist_ok=True)
    json.dump({**body, "receipt_id": rid}, open(os.path.join(aios, "receipts", rid + ".json"), "w"))
    forged_effect = {**_effect(aios, eid), "state": "OBSERVED_SUCCESS", "receipt_id": rid}
    json.dump(forged_effect, open(os.path.join(aios, "effects", eid + ".json"), "w"))
    with pytest.raises(SealError):
        evaluate_persisted_receipt(aios, rid, evaluator_version="e", rubric_version="r", verdict="PASS",
                                   result={"ok": True})
    assert not os.path.isdir(os.path.join(aios, "evaluations")) or not os.listdir(os.path.join(aios, "evaluations"))


def test_f7_concurrent_evaluation_cannot_overwrite(tmp_path, monkeypatch):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    kw = dict(evaluator_version="e", rubric_version="r", result={"ok": True})
    first = evaluate_persisted_receipt(aios, done["receipt_id"], verdict="PASS", **kw)
    # Simulate a racer that passed the existence pre-check before the first write landed.
    real_exists = os.path.exists
    monkeypatch.setattr(os.path, "exists", lambda p: False if "evaluations" in str(p) else real_exists(p))
    with pytest.raises(ValueError, match="already recorded"):
        evaluate_persisted_receipt(aios, done["receipt_id"], verdict="FAIL", **kw)
    monkeypatch.undo()
    stored = json.load(open(os.path.join(aios, "evaluations", first.evaluation_id + ".json")))
    assert stored["verdict"] == "PASS"


# ------------------------------------------------------------------ F8: process death inside commit_batch

@pytest.mark.parametrize("die_after", [1, 2, 3])
def test_f8_process_killed_mid_observation_batch_rolls_forward_consistently(tmp_path, die_after):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)

    def run_and_die():
        calls = {"n": 0}
        real = mutation._replace

        def counted(src, dst):
            real(src, dst)
            if "receipts" in dst or calls["n"]:
                calls["n"] += 1
                if calls["n"] >= die_after:
                    os._exit(137)
        mutation._replace = counted
        execute(aios, cid, pid, "op-1", ACTOR, Provider())
    p = CTX.Process(target=run_and_die)
    p.start()
    p.join(30)
    assert p.exitcode == 137
    eid = _only_effect_id(aios)
    # Any reader goes through recover_pending: the journaled batch is rolled forward,
    # never observed half-applied.
    (rname,) = os.listdir(os.path.join(aios, "receipts"))
    receipt = load_receipt(aios, rname.removesuffix(".json"))
    eff = _effect(aios, eid)
    assert eff["state"] == "OBSERVED_SUCCESS" and eff["receipt_id"] == receipt["receipt_id"]
    assert os.path.exists(os.path.join(aios, "events", f"effect-{eid}-OBSERVED_SUCCESS-attempt-1.json"))


# ------------------------------------------------------------------ real kill before receipt

def test_real_process_kill_after_provider_success_is_reconciled_not_retried(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    ledger = str(tmp_path / "ledger.json")

    def run_and_die():
        runtime.observe = lambda *a, **k: os._exit(137)
        execute(aios, cid, pid, "op-1", ACTOR, FileProvider(ledger))
    p = CTX.Process(target=run_and_die)
    p.start()
    p.join(30)
    assert p.exitcode == 137
    eid = _only_effect_id(aios)
    recover_interrupted(aios, eid, ACTOR)
    with pytest.raises(TransitionError):
        retry_dispatch(aios, eid, ACTOR, f"{eid}:attempt:2", PROVIDER, 2, _explicit(eid, 2))
    done = runtime.reconcile_unknown_attempt(aios, eid, ACTOR, FileProvider(ledger))
    assert done["state"] == "OBSERVED_SUCCESS"
    assert len(json.load(open(ledger))) == 1
