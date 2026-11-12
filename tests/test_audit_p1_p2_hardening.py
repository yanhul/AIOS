# AIOS-CONTRACT: effect authority enforces actor/provider, CAS transitions, issued retry authority,
#                attempt-bound evidence; subprocess adapters enforce live resource bounds.
# AIOS-REGRESSION: Audit F-01..F-06 (direct dispatch authz, read-validate-write race, forged retry
#                  dict, nested evidence replay, post-capture output cap, PCB adapter unbounded).
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Concurrency, direct low-level API authorization, evidence replay, process-tree kill.
# AIOS-BASELINE: Extends M6 effect/runtime and adapter regression suites.

import json
import os
import subprocess
import sys
import threading
import time

import pytest

from adapters.bounded_process import OutputLimitExceeded, run_bounded
from adapters.pcb_eda.adapter import run_kit
from core import effect_authority as ea
from core.effect_authority import (
    dispatch, issue_retry_authorization, observe, retry_dispatch, unknown,
)
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.pcb_eda import PcbEdaRequest
from core.runtime import ProviderReceipt, execute
from tests.test_m6_effect_authority import _effect
from tests.test_m6_runtime import setup_authority

ACTOR = "agent-1"
PROVIDER = "provider-1"


def _a1(effect):
    return f"{effect['effect_id']}:attempt:1"


def _ev(run_id, provider=PROVIDER, evidence_id="EV-1"):
    return EvidenceRecord(evidence_id=evidence_id, level="OBSERVED", source_ref="provider://x",
                          claim="done", run_id=run_id, provider=provider).as_record()


def _to_unknown(tmp_path, effect):
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _a1(effect), PROVIDER)
    return unknown(str(tmp_path), effect["effect_id"], ACTOR, "timeout")


# --- F-01 ------------------------------------------------------------------

def test_f01_dispatch_rejects_non_owner_actor(tmp_path):
    effect = _effect(tmp_path)
    with pytest.raises(TransitionError, match="actor"):
        dispatch(str(tmp_path), effect["effect_id"], "intruder", _a1(effect), PROVIDER)
    assert ea._load(ea._path(str(tmp_path), effect["effect_id"]))["state"] == "PLANNED"


def test_f01_dispatch_rejects_provider_outside_contract(tmp_path):
    effect = _effect(tmp_path)
    with pytest.raises(TransitionError, match="provider is not authorized"):
        dispatch(str(tmp_path), effect["effect_id"], ACTOR, _a1(effect), "provider-evil")
    assert ea._load(ea._path(str(tmp_path), effect["effect_id"]))["state"] == "PLANNED"


def test_f01_retry_rejects_provider_substitution(tmp_path):
    effect = _effect(tmp_path)
    _to_unknown(tmp_path, effect)
    auth = issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    with pytest.raises(TransitionError, match="provider is not authorized"):
        retry_dispatch(str(tmp_path), effect["effect_id"], ACTOR,
                       f"{effect['effect_id']}:attempt:2", "provider-evil", 2, auth)


# --- F-02 ------------------------------------------------------------------

def test_f02_stale_snapshot_cannot_overwrite_concurrent_dispatch(tmp_path):
    effect = _effect(tmp_path)
    stale = ea._load(ea._path(str(tmp_path), effect["effect_id"]))  # worker B reads PLANNED
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _a1(effect), PROVIDER)  # worker A wins
    with pytest.raises(TransitionError, match="concurrent modification"):
        ea._transition_dispatch(str(tmp_path), stale, ACTOR, attempt=1,
                                attempt_id=_a1(effect), provider="provider-b")
    persisted = ea._load(ea._path(str(tmp_path), effect["effect_id"]))
    assert persisted["provider"] == PROVIDER and persisted["state"] == "DISPATCHED"


def test_f02_concurrent_dispatch_has_exactly_one_winner(tmp_path):
    effect = _effect(tmp_path)
    barrier = threading.Barrier(4)
    results = []

    def worker():
        barrier.wait()
        try:
            dispatch(str(tmp_path), effect["effect_id"], ACTOR, _a1(effect), PROVIDER)
            results.append("ok")
        except (TransitionError, ValueError) as exc:
            results.append(type(exc).__name__)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1, results


def test_f02_concurrent_retry_consumes_authorization_once(tmp_path):
    effect = _effect(tmp_path)
    _to_unknown(tmp_path, effect)
    auth = issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    barrier = threading.Barrier(3)
    results = []

    def worker():
        barrier.wait()
        try:
            retry_dispatch(str(tmp_path), effect["effect_id"], ACTOR,
                           f"{effect['effect_id']}:attempt:2", PROVIDER, 2, auth)
            results.append("ok")
        except TransitionError:
            results.append("rejected")

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1, results


# --- F-03 ------------------------------------------------------------------

def test_f03_caller_built_explicit_dict_is_rejected(tmp_path):
    effect = _effect(tmp_path)
    _to_unknown(tmp_path, effect)
    forged = {"mode": "EXPLICIT", "effect_id": effect["effect_id"], "attempt": 2}
    with pytest.raises(TransitionError, match="AIOS-issued"):
        retry_dispatch(str(tmp_path), effect["effect_id"], ACTOR,
                       f"{effect['effect_id']}:attempt:2", PROVIDER, 2, forged)


def test_f03_actor_cannot_self_authorize_retry(tmp_path):
    effect = _effect(tmp_path)
    _to_unknown(tmp_path, effect)
    with pytest.raises(TransitionError, match="issuer"):
        issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, ACTOR, "r")


def test_f03_authorization_is_single_use_and_records_provenance(tmp_path):
    effect = _effect(tmp_path)
    _to_unknown(tmp_path, effect)
    auth = issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "manual reconcile")
    assert auth["issuer"] == "operator:x" and auth["reason"] == "manual reconcile"
    assert auth["unknown_reason"] == "timeout" and auth["status"] == "ISSUED"
    retry_dispatch(str(tmp_path), effect["effect_id"], ACTOR, f"{effect['effect_id']}:attempt:2", PROVIDER, 2, auth)
    path = os.path.join(str(tmp_path), ea.RETRY_AUTH_DIR, auth["authorization_id"] + ".json")
    with open(path, encoding="utf-8") as fh:
        stored = json.load(fh)
    assert stored["status"] == "CONSUMED"
    assert stored["consumed_by_attempt_id"] == f"{effect['effect_id']}:attempt:2"


def test_f03_tampered_authorization_record_is_rejected(tmp_path):
    effect = _effect(tmp_path)
    _to_unknown(tmp_path, effect)
    auth = issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    path = os.path.join(str(tmp_path), ea.RETRY_AUTH_DIR, auth["authorization_id"] + ".json")
    with open(path, encoding="utf-8") as fh:
        rec = json.load(fh)
    rec["issuer"] = "someone-else"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh)
    with pytest.raises(TransitionError, match="integrity"):
        retry_dispatch(str(tmp_path), effect["effect_id"], ACTOR,
                       f"{effect['effect_id']}:attempt:2", PROVIDER, 2, auth)


# --- F-04 ------------------------------------------------------------------

def test_f04_observe_rejects_evidence_from_previous_attempt(tmp_path):
    effect = _effect(tmp_path)
    _to_unknown(tmp_path, effect)
    auth = issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    a2 = f"{effect['effect_id']}:attempt:2"
    retry_dispatch(str(tmp_path), effect["effect_id"], ACTOR, a2, PROVIDER, 2, auth)
    replayed = _ev(run_id=_a1(effect))  # digest-valid, same provider, OLD attempt
    with pytest.raises(ValueError, match="run_id"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS",
                {"attempt_id": a2, "provider": PROVIDER, "evidence": replayed})


def test_f04_observe_rejects_evidence_not_bound_to_receipt(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _a1(effect), PROVIDER)
    with pytest.raises(ValueError, match="artifact_ref"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS",
                {"attempt_id": _a1(effect), "provider": PROVIDER,
                 "observation": {"status": "ok"}, "evidence": _ev(run_id=_a1(effect))})


class _SmugglingAdapter:
    name = "fake-provider"

    def execute(self, *, contract, effect, attempt_id):
        old = EvidenceRecord(evidence_id="EV-old", level="VERIFIED_DIGITAL", source_ref="old",
                             claim="old run", run_id="old-run", provider=self.name).as_record()
        return ProviderReceipt(provider=self.name, effect_id=effect["effect_id"], attempt_id=attempt_id,
                               provider_operation_id="op", outcome="OBSERVED_SUCCESS",
                               observation={"status": "ok", "evidence": old})


def test_f04_runtime_never_promotes_provider_supplied_evidence(tmp_path):
    _c, cid, pid = setup_authority(tmp_path)
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", _SmugglingAdapter())
    assert result["state"] == "OBSERVED_SUCCESS"
    evidence = result["provider_observation"]["evidence"]
    assert evidence["run_id"] == result["attempt_id"]
    assert evidence["level"] == "OBSERVED"
    assert evidence["evidence_id"] != "EV-old"
    # provider's claim is retained only as raw observation data
    assert result["provider_observation"]["observation"]["evidence"]["evidence_id"] == "EV-old"


# --- F-05 / F-06 -----------------------------------------------------------

def test_f05_stdout_flood_is_killed_before_buffering_everything():
    start = time.monotonic()
    with pytest.raises(OutputLimitExceeded) as info:
        run_bounded([sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x'*65536)"],
                    timeout=30, max_stdout_bytes=1024, max_stderr_bytes=1024)
    assert info.value.stream == "stdout"
    assert time.monotonic() - start < 10


def test_f05_stderr_is_capped_too():
    with pytest.raises(OutputLimitExceeded) as info:
        run_bounded([sys.executable, "-c", "import sys\nwhile True: sys.stderr.write('x'*65536)"],
                    timeout=30, max_stdout_bytes=1024, max_stderr_bytes=1024)
    assert info.value.stream == "stderr"


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_f05_timeout_kills_process_tree(tmp_path):
    pidfile = tmp_path / "child.pid"
    script = ("import subprocess,sys,time\n"
              "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
              f"open({str(pidfile)!r},'w').write(str(p.pid))\n"
              "time.sleep(60)\n")
    with pytest.raises(subprocess.TimeoutExpired) as info:
        run_bounded([sys.executable, "-c", script], timeout=1.5,
                    max_stdout_bytes=1024, max_stderr_bytes=1024)
    assert info.value.cleanup["exited"] is True
    grandchild = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        # reap if it became our zombie (it should not: it belongs to init)
        time.sleep(0.05)
    else:
        pytest.fail("grandchild survived process-tree kill")


def _kit(tmp_path, body):
    kit = tmp_path / "kit"
    (kit / "tools/altium-audit").mkdir(parents=True)
    (kit / "tools/altium-audit/audit_kit.py").write_text(body, encoding="utf-8")
    inp = tmp_path / "in"
    inp.mkdir()
    return PcbEdaRequest(task_id="t", input_dir=str(inp), output_dir=str(tmp_path / "out"),
                         kit_root=str(kit), config=None, repair=False, max_retries=0, phase="PCB")


def test_f06_pcb_adapter_times_out(tmp_path):
    req = _kit(tmp_path, "import time; time.sleep(60)\n")
    with pytest.raises(TimeoutError):
        run_kit(req, timeout_seconds=1)


def test_f06_pcb_adapter_caps_output(tmp_path):
    req = _kit(tmp_path, "import sys\nwhile True: sys.stdout.write('x'*65536)\n")
    with pytest.raises(ValueError, match="output limit"):
        run_kit(req, timeout_seconds=30, max_output_bytes=4096)


def test_f06_pcb_adapter_rejects_output_inside_input(tmp_path):
    req = _kit(tmp_path, "pass\n")
    bad = PcbEdaRequest(task_id="t", input_dir=req.input_dir, output_dir=req.input_dir,
                        kit_root=req.kit_root, config=None, repair=False, max_retries=0, phase="PCB")
    with pytest.raises(PermissionError):
        run_kit(bad)
