# AIOS-CONTRACT: P0 external-effect authority under adversarial review (PR #126 review F1–F9)
# AIOS-REGRESSION: Forged/edited authority JSON, racing processes, non-idempotent resume, unbound
#                  evidence, provider substitution and mid-batch process death must all fail closed.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Seals defend against writers without the deployment secret only; provider
#                    authenticity (provider-signed responses) is NOT covered. Races are forced with
#                    real forked processes + barriers on Linux (fcntl); Windows locking not exercised.
# AIOS-BASELINE: e6c2aed (484 passed, 1 skipped); re-review fixes on top of 32e1c04

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

# Only tests that fork real processes are POSIX-only; seal/receipt/evidence/CAS logic
# tests must keep running on every platform (re-review F9).
posix_only = pytest.mark.skipif(os.name != "posix", reason="uses fork + os._exit process tests")
CTX = mp.get_context("fork") if os.name == "posix" else None


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
    from core.record_seal import seal as _seal
    _forge_reconciliation(aios, eff)
    path = os.path.join(aios, "reconciliations", f"{eff['effect_id']}-attempt-1.json")
    monkeypatch.setenv(SEAL_ENV, "attacker-key")
    forged = _seal(json.load(open(path)))  # well-formed seal, untrusted key
    monkeypatch.setenv(SEAL_ENV, "aios-test-only-seal-secret")
    json.dump(forged, open(path, "w"))
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
    with pytest.raises(TransitionError, match="not configured"):  # SealError or authority rejection
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


@posix_only
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


@posix_only
def test_f2_two_processes_cannot_both_dispatch_initial_attempt(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    eff = ea.create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    eid = eff["effect_id"]
    out = _race(aios, 2, lambda i: dispatch(aios, eid, ACTOR, f"{eid}:attempt:1", PROVIDER), "_load_current_cas")
    assert sorted(r[0] for r in out) == ["err", "ok"], out


@posix_only
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

@posix_only
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

@posix_only
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

@posix_only
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


# ================================================================== re-review of 32e1c04

# ------------------------------------------------------------------ F8: stale journal vs newer write

_REL = os.path.join("effects", "E-stale.json")


def _read_rel(aios):
    return json.load(open(os.path.join(aios, _REL)))


def _leave_pending_journal(aios, payloads, real_kill):
    """Writer A journals ``payloads`` and dies before replacing any destination."""
    if real_kill:
        def die():
            mutation._replace = lambda src, dst: os._exit(137)
            mutation.commit_batch(aios, payloads)
        p = CTX.Process(target=die)
        p.start()
        p.join(30)
        assert p.exitcode == 137
    else:
        real = mutation._replace

        def boom(src, dst):
            raise OSError("simulated crash before replace")
        mutation._replace = boom
        try:
            with pytest.raises(OSError):
                mutation.commit_batch(aios, payloads)
        finally:
            mutation._replace = real
    staging = os.path.join(aios, ".staging")
    assert any(os.path.isfile(os.path.join(staging, b, "journal.json")) for b in os.listdir(staging))


@pytest.mark.parametrize("real_kill", [
    pytest.param(True, marks=posix_only, id="forked-process-killed"),
    pytest.param(False, id="in-process-crash"),
])
def test_pending_recovery_never_overwrites_later_valid_write(tmp_path, real_kill):
    aios = str(tmp_path)
    mutation.commit_batch(aios, [(_REL, {"version": 1})])
    _leave_pending_journal(aios, [(_REL, {"version": 2})], real_kill)
    assert _read_rel(aios) == {"version": 1}  # A never replaced the destination

    mutation.commit_batch(aios, [(_REL, {"version": 3})])  # B: valid commit, NO expect
    assert _read_rel(aios) == {"version": 3}

    mutation.recover_pending(aios)  # any later reader
    assert _read_rel(aios) == {"version": 3}, "stale journal rolled forward over a newer commit"
    assert not os.listdir(os.path.join(aios, ".staging"))


@pytest.mark.parametrize("real_kill", [
    pytest.param(True, marks=posix_only, id="forked-process-killed"),
    pytest.param(False, id="in-process-crash"),
])
def test_unexpected_commit_rolls_pending_batch_forward_first(tmp_path, real_kill):
    """B (no expect) must see A's journaled batch applied atomically before its own write."""
    aios = str(tmp_path)
    other = os.path.join("effects", "E-other.json")
    mutation.commit_batch(aios, [(_REL, {"version": 1}), (other, {"version": 1})])
    _leave_pending_journal(aios, [(_REL, {"version": 2}), (other, {"version": 2})], real_kill)
    mutation.commit_batch(aios, [(_REL, {"version": 3})])
    mutation.recover_pending(aios)
    assert _read_rel(aios) == {"version": 3}
    assert json.load(open(os.path.join(aios, other))) == {"version": 2}  # A's batch is not half-lost


# ------------------------------------------------------------------ F3: forged idempotency declaration

class CountingProvider(Provider):
    """NOT idempotent: every execute() is a new side effect, persisted on disk."""

    def __init__(self, ledger, idempotent_claim):
        super().__init__()
        self.ledger = ledger
        self.idempotent_attempt_ids = idempotent_claim

    def _read(self):
        return json.load(open(self.ledger)) if os.path.exists(self.ledger) else []

    def execute(self, *, contract, effect, attempt_id):
        led = self._read()
        led.append(attempt_id)
        json.dump(led, open(self.ledger, "w"))
        self.applied[attempt_id] = f"op-{len(led)}"
        return self._receipt(effect, attempt_id, f"op-{len(led)}")

    def reconcile(self, *, effect, attempt_id):
        self.applied = {a: f"op-{i + 1}" for i, a in enumerate(self._read())}
        return super().reconcile(effect=effect, attempt_id=attempt_id)


def _dispatched_and_applied(tmp_path, metadata=()):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    if metadata:
        from core.capabilities import Capability, CapabilityRegistry
        fresh = CapabilityRegistry()
        for c in CapabilityRegistry.load(aios).snapshot()["capabilities"]:
            if c["capability_id"] == PROVIDER:
                c = {**c, "metadata": [list(m) for m in metadata]}
            fresh.register(Capability.from_dict(c))
        fresh.persist(aios, "test-fixture")
    eff = ea.create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    eff = dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:1", PROVIDER)
    ledger = str(tmp_path / "count.json")
    # The provider applied the side effect; the process died before observe().
    CountingProvider(ledger, False).execute(contract={}, effect=eff, attempt_id=eff["attempt_id"])
    contract = __import__("core.authority", fromlist=["load_contract"]).load_contract(aios, cid)
    return aios, contract, eff, ledger


def test_f3_adapter_self_declared_idempotency_is_not_trusted(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(tmp_path)  # registry attests nothing
    liar = CountingProvider(ledger, idempotent_claim=True)
    done = resume_attempt(aios, contract, eff, ACTOR, liar, None)
    assert len(json.load(open(ledger))) == 1, "forged idempotency declaration caused a second side effect"
    assert done["state"] == "OBSERVED_SUCCESS"
    assert load_receipt(aios, done["receipt_id"])["recorded_via"] == "reconciliation"


def test_f3_caller_supplied_contract_cannot_grant_idempotency(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(tmp_path)
    forged = {**contract, "capabilities": [f"{PROVIDER}@999"]}  # not the persisted contract
    with pytest.raises(PermissionError, match="differs from the contract bound"):
        resume_attempt(aios, forged, eff, ACTOR, CountingProvider(ledger, True), None)
    assert len(json.load(open(ledger))) == 1


def test_f3_registry_attestation_without_adapter_declaration_still_reconciles(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(
        tmp_path, metadata=(("idempotent_attempt_ids", "true"),))
    resume_attempt(aios, contract, eff, ACTOR, CountingProvider(ledger, False), None)
    assert len(json.load(open(ledger))) == 1


class DedupingProvider(CountingProvider):
    """Genuinely idempotent: one external operation per attempt_id, however often it is sent."""

    def execute(self, *, contract, effect, attempt_id):
        led = self._read()
        if attempt_id not in led:
            led.append(attempt_id)
            json.dump(led, open(self.ledger, "w"))
        op = f"op-{led.index(attempt_id) + 1}"
        self.applied[attempt_id] = op
        return self._receipt(effect, attempt_id, op)


def test_f3_registry_attested_idempotent_provider_is_resumed_without_second_side_effect(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(
        tmp_path, metadata=(("idempotent_attempt_ids", "true"),))
    prov = DedupingProvider(ledger, True)
    done = resume_attempt(aios, contract, eff, ACTOR, prov, None)
    assert json.load(open(ledger)) == [eff["attempt_id"]]  # external ledger: still ONE operation
    receipt = load_receipt(aios, done["receipt_id"])
    assert receipt["recorded_via"] == "observe"  # re-sent, not reconciled
    assert receipt["provider_operation_id"] == "op-1"  # the provider returned the original operation


def test_f3_tampered_registry_metadata_cannot_grant_idempotent_resume(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(tmp_path)  # sealed, no idempotency
    path = os.path.join(aios, "capabilities", "capability_registry.json")
    reg = json.load(open(path))
    for c in reg["capabilities"]:
        if c["capability_id"] == PROVIDER:
            c["metadata"] = [["idempotent_attempt_ids", "true"]]
    json.dump(reg, open(path, "w"))  # seal kept, content edited
    with pytest.raises(TransitionError, match="seal does not match"):  # authority now refuses outright
        resume_attempt(aios, contract, eff, ACTOR, CountingProvider(ledger, True), None)
    assert len(json.load(open(ledger))) == 1


def test_f3_unsealed_registry_cannot_grant_idempotent_resume(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(
        tmp_path, metadata=(("idempotent_attempt_ids", "true"),))
    path = os.path.join(aios, "capabilities", "capability_registry.json")
    json.dump(unsealed_body(json.load(open(path))), open(path, "w"))  # downgrade to unsealed
    with pytest.raises(TransitionError, match="not sealed"):
        resume_attempt(aios, contract, eff, ACTOR, CountingProvider(ledger, True), None)
    assert len(json.load(open(ledger))) == 1


def test_f3_resume_cannot_substitute_another_contract_provider(tmp_path):
    """Dispatched to A; B is in the contract and attested idempotent; resume with B must be refused."""
    aios = str(tmp_path)
    from core.capabilities import Capability, CapabilityRegistry
    from core.authority import load_contract, persist_contract, persist_permit
    from tests.test_m6_runtime import contract as make_contract
    from core.authority import contract_identity
    from core.policy_registry import persist_policy
    reg = CapabilityRegistry()
    reg.register(Capability(PROVIDER, "1", "test-fixture", "test", status="ACTIVE"))
    reg.register(Capability("provider-b", "1", "test-fixture", "test", status="ACTIVE",
                            metadata=(("idempotent_attempt_ids", "true"),)))
    reg.persist(aios, "test-fixture")
    policy = persist_policy(aios, {"policy_type": "GOVERNING_POLICY", "name": "ab-fixture"})
    c = make_contract(policy, 1)
    c["capabilities"] = [f"{PROVIDER}@1", "provider-b@1"]
    cid = contract_identity(c)
    persist_contract(aios, c)
    pid = persist_permit(aios, c, "root")["permit_id"]
    eff = ea.create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    eff = dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:1", PROVIDER)
    ledger_a, ledger_b = str(tmp_path / "a.json"), str(tmp_path / "b.json")
    CountingProvider(ledger_a, False).execute(contract={}, effect=eff, attempt_id=eff["attempt_id"])

    b = DedupingProvider(ledger_b, True)
    b.name = "provider-b"
    with pytest.raises(PermissionError, match="differs from the dispatched provider"):
        resume_attempt(aios, load_contract(aios, cid), eff, ACTOR, b, None)
    assert not os.path.exists(ledger_b), "provider B performed a side effect for A's attempt"
    assert len(json.load(open(ledger_a))) == 1
    assert _effect(aios, eff["effect_id"])["state"] == "DISPATCHED"


# ------------------------------------------------------------------ F1: sealed -> unsealed downgrade

def test_f1_stripping_seal_from_genuine_reconciliation_is_rejected(tmp_path):
    aios, _, _, eff = _unknown_effect(tmp_path)
    reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", _status_evidence(eff))
    path = os.path.join(aios, "reconciliations", f"{eff['effect_id']}-attempt-1.json")
    rec = json.load(open(path))
    assert "seal" in rec
    json.dump(unsealed_body(rec), open(path, "w"))
    with pytest.raises(SealError, match="not sealed"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", PROVIDER, 2,
                       _explicit(eff["effect_id"], 2))
    assert _effect(aios, eff["effect_id"])["state"] == "UNKNOWN"


# ------------------------------------------------------------------ F2: remaining CAS mutation path

@posix_only
def test_f2_two_processes_cannot_both_reconcile(tmp_path):
    aios, _, _, eff = _unknown_effect(tmp_path)
    eid = eff["effect_id"]

    def rec(i):
        verdict = "NOT_APPLIED" if i == 0 else "INCONCLUSIVE"
        reconcile_effect(aios, eid, ACTOR, verdict, _status_evidence(eff, verdict.lower()))
    out = _race(aios, 2, rec, "_load_current_cas")
    assert sorted(r[0] for r in out) == ["err", "ok"], out
    assert len(os.listdir(os.path.join(aios, "reconciliations"))) == 1


# ------------------------------------------------------------------ F7: real two-process evaluation race

@posix_only
def test_f7_two_processes_cannot_both_record_evaluation(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    rid = done["receipt_id"]

    def evaluate(i):
        evaluate_persisted_receipt(aios, rid, evaluator_version="e", rubric_version="r",
                                   verdict="PASS" if i == 0 else "FAIL", result={"i": i})
    # Barrier after load_receipt: both processes pass the existence pre-check before either writes.
    out = _race(aios, 2, evaluate, "load_receipt")
    assert sorted(r[0] for r in out) == ["err", "ok"], out
    assert any("already recorded" in r[1] for r in out if r[0] == "err"), out
    (name,) = os.listdir(os.path.join(aios, "evaluations"))
    winner = [r[1] for r in out if r[0] == "ok"][0]
    assert json.load(open(os.path.join(aios, "evaluations", name)))["verdict"] == ("PASS" if winner == 0 else "FAIL")


# ------------------------------------------------------------------ F1: key rotation

def test_f1_rotation_window_verifies_previous_key_and_reseals(tmp_path, monkeypatch):
    from core.record_seal import PREVIOUS_SEAL_ENV, require_seal, reseal
    aios, _, _, eff = _unknown_effect(tmp_path)
    reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", _status_evidence(eff))
    path = os.path.join(aios, "reconciliations", f"{eff['effect_id']}-attempt-1.json")
    old_key = os.environ["AIOS_RECORD_SEAL_SECRET"]
    monkeypatch.setenv("AIOS_RECORD_SEAL_SECRET", "rotated-key-b")

    rec = json.load(open(path))
    with pytest.raises(SealError, match="different key"):
        require_seal(rec)  # retired key not listed => fail closed
    monkeypatch.setenv(PREVIOUS_SEAL_ENV, old_key)
    require_seal(rec)  # rotation window: old record still verifies
    fresh = reseal(rec)
    monkeypatch.delenv(PREVIOUS_SEAL_ENV)
    require_seal(fresh)  # resealed under the current key only
    with pytest.raises(SealError):
        reseal({**rec, "verdict": "INCONCLUSIVE"})  # reseal never launders an edited record


def test_f1_rotation_window_does_not_trust_unlisted_keys(tmp_path, monkeypatch):
    from core.record_seal import PREVIOUS_SEAL_ENV, require_seal, seal
    monkeypatch.setenv("AIOS_RECORD_SEAL_SECRET", "attacker")
    forged = seal({"record_type": "X", "v": 1})
    monkeypatch.setenv("AIOS_RECORD_SEAL_SECRET", "current")
    monkeypatch.setenv(PREVIOUS_SEAL_ENV, "retired-1, retired-2")
    with pytest.raises(SealError, match="different key"):
        require_seal(forged)


# ------------------------------------------------------------------ @9fd7d5c: contract substitution on resume

def test_resume_rejects_caller_contract_with_same_provider_but_different_terms(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(
        tmp_path, metadata=(("idempotent_attempt_ids", "true"),))
    c2 = {k: v for k, v in contract.items() if k not in ("contract_id", "record_type")}
    c2["scope"] = "widened-scope"  # provider and external_effect still valid
    seen = []
    prov = DedupingProvider(ledger, True)
    real = prov.execute
    prov.execute = lambda **kw: (seen.append(kw["contract"]), real(**kw))[1]
    with pytest.raises(PermissionError, match="differs from the contract bound"):
        resume_attempt(aios, c2, eff, ACTOR, prov, None)
    assert not seen and json.load(open(ledger)) == [eff["attempt_id"]]


def test_execute_attempt_hands_provider_only_the_stored_contract(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(
        tmp_path, metadata=(("idempotent_attempt_ids", "true"),))
    seen = []
    prov = DedupingProvider(ledger, True)
    real = prov.execute
    prov.execute = lambda **kw: (seen.append(kw["contract"]), real(**kw))[1]
    resume_attempt(aios, dict(contract), eff, ACTOR, prov, None)
    from core.contract import contract_identity as _cid
    from core.authority import _canonical_contract
    assert seen and _cid(_canonical_contract(seen[0])) == eff["contract_id"]


def test_execute_attempt_direct_call_rejects_substituted_contract(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(tmp_path)
    c2 = {k: v for k, v in contract.items() if k not in ("contract_id", "record_type")}
    c2["input_digest"] = "sha256:" + "0" * 64
    with pytest.raises(PermissionError):
        runtime.execute_attempt(aios, c2, eff, ACTOR, CountingProvider(ledger, False), eff["attempt_id"])
    assert len(json.load(open(ledger))) == 1


# ------------------------------------------------------------------ @9fd7d5c: registry seal on authority paths

def _registry_path(aios):
    return os.path.join(aios, "capabilities", "capability_registry.json")


def _tamper_registry(aios, mutate, keep_seal=True):
    from core.record_seal import unsealed_body as _ub
    reg = json.load(open(_registry_path(aios)))
    mutate(reg)
    json.dump(reg if keep_seal else _ub(reg), open(_registry_path(aios), "w"))


@pytest.mark.parametrize("keep_seal", [True, False], ids=["edited-keeps-seal", "downgraded-unsealed"])
def test_authority_rejects_tampered_registry_promoting_candidate(tmp_path, keep_seal):
    from core.authority import authorize
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    authorize(aios, cid, pid)  # baseline OK

    def promote(reg):
        reg["capabilities"].append({"capability_id": "rogue", "version": "1", "owner": "x", "kind": "x",
                                    "status": "ACTIVE"})
    _tamper_registry(aios, promote, keep_seal)
    with pytest.raises(TransitionError, match="capability authority rejected"):
        authorize(aios, cid, pid)
    with pytest.raises(TransitionError):
        execute(aios, cid, pid, "op-2", ACTOR, Provider())


def test_persist_contract_rejects_unsealed_registry_and_migration_is_explicit(tmp_path, monkeypatch):
    from core.authority import authorize
    from core.capabilities import CapabilityError, CapabilityRegistry
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    _tamper_registry(aios, lambda reg: None, keep_seal=False)  # legacy unsealed file
    with pytest.raises(TransitionError):
        authorize(aios, cid, pid)
    monkeypatch.delenv(SEAL_ENV)
    with pytest.raises(CapabilityError, match="not configured"):
        CapabilityRegistry.migrate_to_sealed(aios, "operator")
    monkeypatch.setenv(SEAL_ENV, "aios-test-only-seal-secret")
    CapabilityRegistry.migrate_to_sealed(aios, "operator")
    authorize(aios, cid, pid)  # sealed by explicit operator action => authority restored
    with pytest.raises(CapabilityError, match="already carries a seal"):
        CapabilityRegistry.migrate_to_sealed(aios, "operator")


# ------------------------------------------------------------------ @444e578: direct execute_attempt binding

def _fresh_dispatched(tmp_path):
    from core.authority import load_contract
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    eff = ea.create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    eff = dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:1", PROVIDER)
    return aios, load_contract(aios, cid), eff, str(tmp_path / "count.json")


def _ledger(path):
    return json.load(open(path)) if os.path.exists(path) else []


def test_execute_attempt_replay_of_stale_dispatched_copy_never_reaches_provider(tmp_path):
    aios, contract, eff, ledger = _fresh_dispatched(tmp_path)
    stale = dict(eff)
    done = runtime.execute_attempt(aios, contract, eff, ACTOR, CountingProvider(ledger, False), eff["attempt_id"])
    assert done["state"] == "OBSERVED_SUCCESS"
    with pytest.raises(RuntimeError, match="not DISPATCHED"):
        runtime.execute_attempt(aios, contract, stale, ACTOR, CountingProvider(ledger, False), stale["attempt_id"])
    assert len(_ledger(ledger)) == 1, "stale effect copy caused a second side effect"


@pytest.mark.parametrize("field,value", [
    ("logical_operation_id", "op-forged"),
    ("max_attempts", 99),
    ("permit_id", "PERMIT-forged"),
    ("extra_field", "x"),
])
def test_execute_attempt_rejects_edited_effect_and_provider_never_sees_it(tmp_path, field, value):
    aios, contract, eff, ledger = _fresh_dispatched(tmp_path)
    forged = {**eff, field: value}
    with pytest.raises(PermissionError, match="persisted effect"):
        runtime.execute_attempt(aios, contract, forged, ACTOR, CountingProvider(ledger, False), eff["attempt_id"])
    assert _ledger(ledger) == []
    assert _effect(aios, eff["effect_id"])["state"] == "DISPATCHED"


def test_provider_receives_persisted_effect_not_caller_object(tmp_path):
    aios, contract, eff, ledger = _fresh_dispatched(tmp_path)
    seen = {}

    class Spy(CountingProvider):
        def execute(self, *, contract, effect, attempt_id):
            seen["effect"] = effect
            return super().execute(contract=contract, effect=effect, attempt_id=attempt_id)

    runtime.execute_attempt(aios, contract, dict(eff), ACTOR, Spy(ledger, False), eff["attempt_id"])
    assert mutation.canonical_json(seen["effect"]) == mutation.canonical_json(eff)


def test_claimed_attempt_cannot_be_executed_twice_and_resume_reconciles(tmp_path, monkeypatch):
    """Crash after the execution claim: a second direct call is refused before
    the provider; only resume (attested idempotency or reconciliation) continues."""
    aios, contract, eff, ledger = _fresh_dispatched(tmp_path)
    real_run = runtime._run_bound

    def crash_after_side_effect(aios_dir, stored, persisted, actor, adapter, provider_name):
        adapter.execute(contract=dict(stored), effect=dict(persisted), attempt_id=persisted["attempt_id"])
        raise KeyboardInterrupt("process died before observe()")

    monkeypatch.setattr(runtime, "_run_bound", crash_after_side_effect)
    with pytest.raises(KeyboardInterrupt):
        runtime.execute_attempt(aios, contract, eff, ACTOR, CountingProvider(ledger, False), eff["attempt_id"])
    monkeypatch.setattr(runtime, "_run_bound", real_run)
    assert len(_ledger(ledger)) == 1

    with pytest.raises(RuntimeError, match="already claimed"):
        runtime.execute_attempt(aios, contract, eff, ACTOR, CountingProvider(ledger, False), eff["attempt_id"])
    assert len(_ledger(ledger)) == 1, "replayed direct call re-executed a claimed attempt"

    done = resume_attempt(aios, contract, eff, ACTOR, CountingProvider(ledger, True), None)
    assert len(_ledger(ledger)) == 1
    assert done["state"] == "OBSERVED_SUCCESS"
    assert load_receipt(aios, done["receipt_id"])["recorded_via"] == "reconciliation"


def _race_execute(aios, contract, eff, ledger, q):
    try:
        runtime.execute_attempt(aios, contract, eff, ACTOR, CountingProvider(ledger, False), eff["attempt_id"])
        q.put("ok")
    except Exception as exc:  # noqa: BLE001
        q.put(type(exc).__name__)


def test_two_processes_cannot_both_execute_the_same_attempt(tmp_path):
    aios, contract, eff, ledger = _fresh_dispatched(tmp_path)
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    procs = [ctx.Process(target=_race_execute, args=(aios, contract, eff, ledger, q)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    results = [q.get(timeout=5) for _ in procs]
    assert results.count("ok") == 1, results
    assert len(_ledger(ledger)) == 1


def test_resume_rejects_edited_effect_copy(tmp_path):
    aios, contract, eff, ledger = _dispatched_and_applied(tmp_path)
    with pytest.raises(PermissionError, match="persisted effect"):
        resume_attempt(aios, contract, {**eff, "logical_operation_id": "op-x"}, ACTOR,
                       CountingProvider(ledger, True), None)
    assert len(_ledger(ledger)) == 1


# ------------------------------------------------------------------ @444e578 F4: migration TOCTOU

def test_migration_seals_only_the_snapshot_it_checked(tmp_path, monkeypatch):
    from core.capabilities import CapabilityError, CapabilityRegistry
    from core.record_seal import unsealed_body as _ub
    aios = str(tmp_path)
    setup_authority(tmp_path)
    _tamper_registry(aios, lambda reg: None, keep_seal=False)  # legacy unsealed file
    real = CapabilityRegistry._from_data.__func__

    def concurrent_writer(cls, data):
        reg = _ub(json.load(open(_registry_path(aios))))
        reg["capabilities"].append({"capability_id": "rogue", "version": "1", "owner": "x", "kind": "x",
                                    "status": "ACTIVE"})
        json.dump(reg, open(_registry_path(aios), "w"))
        return real(cls, data)

    monkeypatch.setattr(CapabilityRegistry, "_from_data", classmethod(concurrent_writer))
    with pytest.raises(CapabilityError, match="changed during migration"):
        CapabilityRegistry.migrate_to_sealed(aios, "operator")
    on_disk = json.load(open(_registry_path(aios)))
    assert "seal" not in on_disk, "migration sealed content that was not the checked snapshot"
    with pytest.raises(CapabilityError):
        CapabilityRegistry.load(aios, require_sealed=True)
