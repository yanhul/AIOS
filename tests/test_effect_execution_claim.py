"""Adversarial tests for the AIOS execution-claim / CAS boundary.

These use real AIOS file-backed state and real OS processes/threads contending
on the AIOS mutation lock (flock). They prove the properties on a local POSIX
filesystem; they do not prove behaviour on network filesystems.
"""
import json
import multiprocessing as mp
import os
import threading
import time
from unittest import mock

import pytest

import core.effect_authority as ea
from core.effect_authority import create_effect, dispatch, retry_dispatch, unknown

# getattr so the race tests still *run* (and fail) against a pre-fix AIOS.
ExecutionClaimRejected = getattr(ea, "ExecutionClaimRejected", type("Missing", (Exception,), {}))
claim_execution = getattr(ea, "claim_execution", None)
from core.external_effect import load_effects
from core.runtime import ProviderReceipt, execute_attempt
from tests.test_m6_runtime import setup_authority

ACTOR = "agent:test"
PROVIDER = "fake-provider"


class LedgerAdapter:
    name = PROVIDER

    def __init__(self, ledger, delay=0.0):
        self.ledger = str(ledger)
        self.delay = delay

    def execute(self, *, contract, effect, attempt_id):
        fd = os.open(self.ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, (json.dumps({"attempt_id": attempt_id, "pid": os.getpid()}) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        time.sleep(self.delay)
        return ProviderReceipt(provider=self.name, effect_id=effect["effect_id"], attempt_id=attempt_id,
                               provider_operation_id="op-" + attempt_id, outcome="OBSERVED_SUCCESS",
                               observation={"status": "ok"})


def calls(ledger):
    return len(ledger.read_text().splitlines()) if ledger.exists() else 0


def dispatched(tmp_path, max_attempts=1, op="op-1"):
    c, cid, pid = setup_authority(tmp_path, max_attempts)
    eff = create_effect(str(tmp_path), cid, op, ACTOR, pid, "external_effect")
    aid = eff["effect_id"] + ":attempt:1"
    return c, cid, pid, dispatch(str(tmp_path), eff["effect_id"], ACTOR, aid, PROVIDER)


def test_unknown_between_validation_and_provider_call_blocks_execution(tmp_path):
    """Competing DISPATCHED->UNKNOWN lands after execute_attempt's snapshot checks."""
    c, _cid, _pid, eff = dispatched(tmp_path)
    ledger = tmp_path / "ledger"
    import core.runtime as rt
    real = rt._provider_authorized

    def race(contract, name):  # last snapshot check before the provider boundary
        unknown(str(tmp_path), eff["effect_id"], ACTOR, "operator: lease lost elsewhere")
        return real(contract, name)

    with mock.patch.object(rt, "_provider_authorized", side_effect=race):
        with pytest.raises(ExecutionClaimRejected):
            execute_attempt(str(tmp_path), c, eff, ACTOR, LedgerAdapter(ledger), eff["attempt_id"])
    assert calls(ledger) == 0
    assert load_effects(str(tmp_path))[eff["effect_id"]]["state"] == "UNKNOWN"


def test_stale_snapshot_cannot_authorize_after_redispatch(tmp_path):
    c, cid, pid, eff = dispatched(tmp_path, max_attempts=2)
    unknown(str(tmp_path), eff["effect_id"], ACTOR, "ambiguous")
    retry_dispatch(str(tmp_path), eff["effect_id"], ACTOR, eff["effect_id"] + ":attempt:2", PROVIDER, 2)
    ledger = tmp_path / "ledger"
    with pytest.raises(ExecutionClaimRejected):  # attempt-1 snapshot is stale
        execute_attempt(str(tmp_path), c, eff, ACTOR, LedgerAdapter(ledger), eff["attempt_id"])
    assert calls(ledger) == 0
    rec = load_effects(str(tmp_path))[eff["effect_id"]]
    assert rec["state"] == "DISPATCHED" and rec["attempt"] == 2 and "execution_claim" not in rec


def test_claim_is_single_use_and_bound(tmp_path):
    _c, _cid, _pid, eff = dispatched(tmp_path)
    root, eid, aid = str(tmp_path), eff["effect_id"], eff["attempt_id"]
    with pytest.raises(ExecutionClaimRejected):
        claim_execution(root, eid, aid, "other-provider", ACTOR, "h")
    with pytest.raises(ExecutionClaimRejected):
        claim_execution(root, eid, aid, PROVIDER, "agent:other", "h")
    with pytest.raises(ExecutionClaimRejected):
        claim_execution(root, eid, aid, PROVIDER, ACTOR, "h", expected=dict(eff, permit_id="P-forged"))
    claimed = claim_execution(root, eid, aid, PROVIDER, ACTOR, "h1")
    assert claimed["execution_claim"]["holder"] == "h1"
    with pytest.raises(ExecutionClaimRejected, match="already claimed"):
        claim_execution(root, eid, aid, PROVIDER, ACTOR, "h2")


def _worker(root, contract, eff, ledger, barrier, out):
    barrier.wait()
    try:
        execute_attempt(root, contract, eff, ACTOR, LedgerAdapter(ledger, delay=0.2), eff["attempt_id"])
        out.put("executed")
    except ExecutionClaimRejected:
        out.put("rejected")
    except Exception as exc:  # pragma: no cover - surfaced via assertion
        out.put(f"error:{type(exc).__name__}:{exc}")


@pytest.mark.skipif(os.name == "nt", reason="fork-based cross-process test")
def test_concurrent_processes_same_attempt_one_provider_call(tmp_path):
    c, _cid, _pid, eff = dispatched(tmp_path)
    ledger = tmp_path / "ledger"
    ctx = mp.get_context("fork")
    n = 4
    barrier, out = ctx.Barrier(n), ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(str(tmp_path), c, eff, ledger, barrier, out))
             for _ in range(n)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    results = sorted(out.get(timeout=5) for _ in range(n))
    assert results == ["executed"] + ["rejected"] * (n - 1), results
    assert calls(ledger) == 1
    assert load_effects(str(tmp_path))[eff["effect_id"]]["state"] == "OBSERVED_SUCCESS"


def test_concurrent_retry_dispatch_is_compare_and_set(tmp_path):
    """Two retries both read UNKNOWN; only one may consume the attempt."""
    _c, _cid, _pid, eff = dispatched(tmp_path, max_attempts=3)
    root, eid = str(tmp_path), eff["effect_id"]
    unknown(root, eid, ACTOR, "ambiguous")
    real = ea._validate_persisted_effect
    gate = threading.Barrier(2, timeout=2)

    def slow(aios_dir, effect):  # widen the read->write window
        out = real(aios_dir, effect)
        try:
            gate.wait()
        except threading.BrokenBarrierError:
            pass  # serialized by the lock: the second thread never meets the first
        return out

    results = []

    def go():
        try:
            retry_dispatch(root, eid, ACTOR, eid + ":attempt:2", PROVIDER, 2)
            results.append("ok")
        except Exception as exc:
            results.append(type(exc).__name__)

    with mock.patch.object(ea, "_validate_persisted_effect", side_effect=slow):
        ts = [threading.Thread(target=go) for _ in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(10)
    assert sorted(results) == ["TransitionError", "ok"], results
    events = [f for f in os.listdir(os.path.join(root, "events")) if "DISPATCHED-attempt-2" in f]
    assert len(events) == 1


def test_nested_lock_is_reentrant_and_exclusive(tmp_path):
    from core.mutation import mutation_lock
    root = str(tmp_path / "aios")
    entered = threading.Event()

    def other():
        with mutation_lock(root):
            entered.set()

    with mutation_lock(root):
        with mutation_lock(root):
            pass
        t = threading.Thread(target=other)
        t.start()
        assert not entered.wait(0.3)  # other thread blocked while we hold it
    assert entered.wait(5)
    t.join(5)


def test_forged_caller_contract_cannot_grant_provider_capability(tmp_path):
    """A forged caller grant cannot authorize a provider absent from stored policy."""
    contract, cid, pid = setup_authority(tmp_path)
    eff = create_effect(str(tmp_path), cid, "forged-provider-op", ACTOR, pid, "external_effect")
    unauthorized = "unauthorized-provider"
    aid = eff["effect_id"] + ":attempt:1"
    # Dispatch deliberately records the requested provider; execution claim
    # must independently check that provider against the persisted contract.
    eff = dispatch(str(tmp_path), eff["effect_id"], ACTOR, aid, unauthorized)
    forged = dict(contract)
    forged["capabilities"] = list(contract.get("capabilities", [])) + [unauthorized + "@1"]

    class UnauthorizedAdapter(LedgerAdapter):
        name = unauthorized

    ledger = tmp_path / "forged-contract-ledger"
    with pytest.raises(ExecutionClaimRejected, match="persisted contract"):
        execute_attempt(str(tmp_path), forged, eff, ACTOR,
                        UnauthorizedAdapter(ledger), aid)
    assert calls(ledger) == 0
    rec = load_effects(str(tmp_path))[eff["effect_id"]]
    assert "execution_claim" not in rec
