# AIOS-CONTRACT: durable external-effect retry authority
# AIOS-REGRESSION: Prevent ambiguous UNKNOWN effects from retrying without governed authority
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Covers bounded UNKNOWN retry, authority binding, and duplicate-effect prevention
# AIOS-BASELINE: Existing M6 effect/runtime regression suite extended for explicit retry authority

import tempfile
import multiprocessing as mp
import json

import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core import effect_authority
from core.effect_authority import (
    create_effect,
    claim_execution,
    dispatch,
    observe,
    retry_dispatch,
    transition,
    unknown,
)
from core.evidence import EvidenceRecord
from core.mutation import TransitionError, _MutationLock, commit_batch
from core.policy_registry import persist_policy




def test_effect_journal_recovery_runs_inside_same_mutation_lock(tmp_path, monkeypatch):
    _contract, _permit, effect = make_authorized(str(tmp_path))
    real_lock = _MutationLock
    lock_state = {"held": False, "recoveries": 0}

    class TrackingLock:
        def __init__(self, state_dir):
            self.inner = real_lock(state_dir)

        def __enter__(self):
            self.inner.__enter__()
            lock_state["held"] = True
            return self

        def __exit__(self, exc_type, exc, tb):
            lock_state["held"] = False
            return self.inner.__exit__(exc_type, exc, tb)

    def checked_recovery(state_dir):
        assert lock_state["held"], "journal recovery escaped the effect mutation lock"
        lock_state["recoveries"] += 1

    original_authorized_contract = effect_authority._authorized_contract
    authorization_checks = []

    def checked_authorization(*args, **kwargs):
        assert lock_state["held"], "effect authorization escaped the mutation lock"
        authorization_checks.append(True)
        return original_authorized_contract(*args, **kwargs)

    monkeypatch.setattr(effect_authority, "_MutationLock", TrackingLock)
    monkeypatch.setattr(effect_authority, "_recover_pending_unlocked", checked_recovery)
    monkeypatch.setattr(effect_authority, "_authorized_contract", checked_authorization)

    # Idempotent create still revalidates its authority under the same lock.
    effect_authority.create_effect(
        str(tmp_path), contract_identity(_contract), "research-oos",
        "bc-controller", _permit["permit_id"], "process_execution"
    )
    attempt_id = f"{effect['effect_id']}:attempt:1"
    dispatched = dispatch(str(tmp_path), effect["effect_id"], "bc-controller",
                          attempt_id, "research_is_validation")
    assert dispatched["state"] == "DISPATCHED"
    _contract, claimed = effect_authority.claim_execution(
        str(tmp_path), effect["effect_id"], "bc-controller",
        attempt_id, "research_is_validation"
    )
    assert claimed["execution_claimed"] is True
    assert lock_state["recoveries"] == 3
    assert authorization_checks == [True, True, True]


def test_commit_batch_exposes_no_caller_controlled_lock_bypass():
    import inspect
    assert "lock_held" not in inspect.signature(commit_batch).parameters


def _dispatch_race_worker(state_dir, effect_id, barrier, result_queue):
    try:
        barrier.wait(timeout=15)
        result = dispatch(state_dir, effect_id, "bc-controller",
                          f"{effect_id}:attempt:1", "provider-a")
        result_queue.put(("success", result["state"]))
    except Exception as exc:
        result_queue.put(("error", type(exc).__name__, str(exc)))


def make_authorized(td):
    registry = CapabilityRegistry()
    registry.register(Capability("research_is_validation", "1", "test-fixture", "research", status="ACTIVE"))
    registry.persist(td, "test-fixture")
    policy = persist_policy(td, {"policy_type": "GOVERNING_POLICY", "name": "effect-hardening"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "RESEARCH_BC7",
        "scope": "research",
        "actor": "bc-controller",
        "capabilities": ["research_is_validation@1"],
        "input_digest": "sha256:input",
        "allowed_effects": ["process_execution"],
        "evidence_required": ["execution_receipt"],
        "max_attempts": 2,
        "terminal_states": ["PROMOTED", "REJECTED", "HOLD"],
        "policy_digest": policy,
    }
    persist_contract(td, contract)
    permit = persist_permit(td, contract, "AIOS_AUTHORITY")
    effect = create_effect(
        td,
        contract_identity(contract),
        "research-oos",
        "bc-controller",
        permit["permit_id"],
        "process_execution",
    )
    return contract, permit, effect


def test_effect_creation_requires_bound_permit_and_allowed_effect():
    with tempfile.TemporaryDirectory() as td:
        with pytest.raises((ValueError, KeyError, FileNotFoundError, TransitionError)):
            create_effect(td, "fake-contract", "op", "bc-controller", "fake-permit", "process_execution")
        contract, permit, _ = make_authorized(td)
        with pytest.raises(TransitionError):
            create_effect(td, contract_identity(contract), "other", "bc-controller", permit["permit_id"], "forbidden")


def test_initial_dispatch_is_bound_to_effect_attempt_identity():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        with pytest.raises(ValueError):
            dispatch(td, effect["effect_id"], "bc-controller", "arbitrary-attempt", "provider-a")
        updated = dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:1", "provider-a")
        assert updated["state"] == "DISPATCHED"
        assert updated["attempt"] == 1


def test_public_transition_cannot_mutate_identity_or_authority_fields():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        with pytest.raises(TransitionError):
            transition(td, effect["effect_id"], "DISPATCHED", "bc-controller",
                       contract_id="forged-contract", attempt=1,
                       attempt_id=f"{effect['effect_id']}:attempt:1", provider="provider-a")


def test_generic_transition_cannot_enter_dispatched_from_planned():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        with pytest.raises(TransitionError, match="undefined external-effect transition"):
            transition(td, effect["effect_id"], "DISPATCHED", "bc-controller",
                       attempt=1, attempt_id=f"{effect['effect_id']}:attempt:1", provider="provider-a")


def test_unknown_retry_is_blocked_without_independent_issuer():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        dispatch(td, effect["effect_id"], "bc-controller",
                 f"{effect['effect_id']}:attempt:1", "provider-a")
        unknown(td, effect["effect_id"], "bc-controller", "provider timeout")
        with pytest.raises(TransitionError, match="independent issuer verification"):
            retry_dispatch(td, effect["effect_id"], "bc-controller",
                           f"{effect['effect_id']}:attempt:2", "provider-a", 2,
                           {"mode":"EXPLICIT", "effect_id":effect["effect_id"], "attempt":2})
        persisted = json.loads(open(
            f"{td}/effects/{effect['effect_id']}.json", encoding="utf-8"
        ).read())
        assert persisted["state"] == "UNKNOWN"
        assert persisted["attempt"] == 1


def test_concurrent_initial_dispatch_has_exactly_one_winner(tmp_path):
    _contract, _permit, effect = make_authorized(str(tmp_path))
    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    results = ctx.Queue()
    processes = [
        ctx.Process(target=_dispatch_race_worker,
                    args=(str(tmp_path), effect["effect_id"], barrier, results))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(30)
    for process in processes:
        if process.is_alive():
            process.terminate()
            process.join()
    assert [process.exitcode for process in processes] == [0, 0]
    outcomes = [results.get(timeout=5), results.get(timeout=5)]
    assert sum(item[0] == "success" for item in outcomes) == 1, outcomes
    assert sum(item[0] == "error" and item[1] == "TransitionError"
               for item in outcomes) == 1, outcomes
    persisted = json.loads(
        (tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text()
    )
    assert persisted["state"] == "DISPATCHED"
    assert persisted["attempt"] == 1
    assert len(list((tmp_path / "events").glob(
        f"effect-{effect['effect_id']}-DISPATCHED-attempt-1.json"
    ))) == 1



def test_public_transition_cannot_forge_terminal_observation(tmp_path):
    _contract, _permit, effect = make_authorized(str(tmp_path))
    dispatch(str(tmp_path), effect["effect_id"], "bc-controller",
             f"{effect['effect_id']}:attempt:1", "provider-a")
    forged = {
        "attempt_id": f"{effect['effect_id']}:attempt:1",
        "provider": "provider-a",
        "evidence": {"level": "OBSERVED", "claim": "made up"},
    }
    with pytest.raises(TransitionError, match="must use observe"):
        transition(str(tmp_path), effect["effect_id"], "OBSERVED_SUCCESS",
                   "bc-controller", provider_observation=forged)
    persisted = json.loads(
        (tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text()
    )
    assert persisted["state"] == "DISPATCHED"

def test_observation_requires_current_attempt_and_valid_aios_evidence():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        attempt_id = f"{effect['effect_id']}:attempt:1"
        dispatch(td, effect["effect_id"], "bc-controller", attempt_id, "provider-a")
        evidence = EvidenceRecord(
            evidence_id="EV-effect-1",
            level="OBSERVED",
            source_ref="runtime/provider-a",
            claim="execution completed",
            run_id="run-1",
            provider="provider-a",
        ).as_record()
        observation = {"attempt_id": attempt_id, "provider": "provider-a", "evidence": evidence}
        # A caller-computed digest is not independent issuer authentication.
        with pytest.raises(PermissionError, match="independent evidence issuer/verifier"):
            observe(td, effect["effect_id"], "bc-controller", "OBSERVED_SUCCESS", observation)
        persisted = json.loads(open(os.path.join(td, "effects", effect["effect_id"] + ".json"), encoding="utf-8").read())
        assert persisted["state"] == "DISPATCHED"
        with pytest.raises(PermissionError, match="independent evidence issuer/verifier"):
            observe(td, effect["effect_id"], "bc-controller", "OBSERVED_SUCCESS", observation)


def test_tampered_persisted_authority_blocks_future_transition():
    with tempfile.TemporaryDirectory() as td:
        contract, _permit, effect = make_authorized(td)
        dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:1", "provider-a")
        path = f"{td}/effects/{effect['effect_id']}.json"
        import json
        with open(path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)
        rec["policy_digest"] = "tampered-policy"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        with pytest.raises(TransitionError):
            unknown(td, effect["effect_id"], "bc-controller", "should be blocked")


def _claim_race_worker(state_dir, effect_id, attempt_id, barrier, result_queue):
    try:
        barrier.wait(timeout=15)
        _contract, claimed = claim_execution(
            state_dir, effect_id, "bc-controller", attempt_id, "research_is_validation"
        )
        result_queue.put(("success", claimed.get("execution_claimed")))
    except Exception as exc:
        result_queue.put(("error", type(exc).__name__, str(exc)))


def test_concurrent_execution_claim_has_exactly_one_winner(tmp_path):
    _contract, _permit, effect = make_authorized(str(tmp_path))
    attempt_id = f"{effect['effect_id']}:attempt:1"
    dispatch(str(tmp_path), effect["effect_id"], "bc-controller",
             attempt_id, "research_is_validation")
    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    results = ctx.Queue()
    processes = [
        ctx.Process(target=_claim_race_worker,
                    args=(str(tmp_path), effect["effect_id"], attempt_id, barrier, results))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(30)
    for process in processes:
        if process.is_alive():
            process.terminate()
            process.join()
    assert [process.exitcode for process in processes] == [0, 0]
    outcomes = [results.get(timeout=5), results.get(timeout=5)]
    assert sum(item[0] == "success" for item in outcomes) == 1, outcomes
    assert sum(item[0] == "error" and item[1] == "TransitionError"
               for item in outcomes) == 1, outcomes
    persisted = json.loads(
        (tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text()
    )
    assert persisted["execution_claimed"] is True
    assert persisted["execution_claimed_attempt_id"] == attempt_id
    assert len(list((tmp_path / "events").glob(
        f"effect-{effect['effect_id']}-EXECUTION_CLAIMED-attempt-1.json"
    ))) == 1
