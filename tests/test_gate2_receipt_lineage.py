import json

import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch, observe
from core.evidence import EvidenceRecord
from core.policy_registry import persist_policy
from core.receipt import persist_receipt, load_receipt
from core.mutation import TransitionError
from core.evaluation import evaluate, load_evaluation


def setup(tmp_path):
    registry = CapabilityRegistry()
    registry.register(Capability("provider-1", "1", "test-fixture", "test", status="ACTIVE"))
    registry.persist(str(tmp_path), "test-fixture")
    policy = persist_policy(str(tmp_path), {"policy_type": "GOVERNING_POLICY", "name": "receipt-lineage"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "receipt-lineage",
        "scope": "test", "actor": "agent-1", "capabilities": ["provider-1@1"],
        "input_digest": "input", "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"], "max_attempts": 2,
        "terminal_states": ["SUCCESS", "FAILURE"], "policy_digest": policy,
    }
    persist_contract(str(tmp_path), contract)
    permit = persist_permit(str(tmp_path), contract, "root")
    effect = create_effect(str(tmp_path), contract_identity(contract), "op-1",
                           "agent-1", permit["permit_id"], "external_effect")
    effect = dispatch(str(tmp_path), effect["effect_id"], "agent-1",
                      f"{effect['effect_id']}:attempt:1", "provider-1")
    return effect


def receipt(tmp_path, effect, operation="op-1"):
    return persist_receipt(
        str(tmp_path), effect, effect["attempt_id"], effect["provider"],
        operation, "OBSERVED_SUCCESS", {"status": "ok"},
    )


def evidence(effect, rec, **overrides):
    data = {
        "evidence_id": "EV-G2",
        "level": "OBSERVED",
        "source_ref": "provider://" + rec["provider_operation_id"],
        "claim": "execution completed",
        "run_id": effect["attempt_id"],
        "provider": effect["provider"],
        "artifact_ref": rec["provider_operation_id"],
        "receipt_id": rec["receipt_id"],
        "effect_id": effect["effect_id"],
        "attempt_id": effect["attempt_id"],
    }
    data.update(overrides)
    return EvidenceRecord(**data).as_record()


def test_receipt_is_durable_and_immutable(tmp_path):
    effect = setup(tmp_path)
    rec = receipt(tmp_path, effect)
    loaded = load_receipt(str(tmp_path), rec["receipt_id"])
    assert loaded == rec
    path = tmp_path / "receipts" / (rec["receipt_id"] + ".json")
    raw = json.loads(path.read_text())
    raw["observation"] = {"status": "tampered"}
    path.write_text(json.dumps(raw))
    with pytest.raises(TransitionError):
        load_receipt(str(tmp_path), rec["receipt_id"])


def test_wrong_receipt_effect_cannot_satisfy_observation(tmp_path):
    effect = setup(tmp_path)
    rec = receipt(tmp_path, effect)
    forged = json.loads(json.dumps(rec))
    forged["effect_id"] = "EF-forged"
    forged["digest"] = rec["digest"]
    (tmp_path / "receipts" / (rec["receipt_id"] + ".json")).write_text(json.dumps(forged))
    ev = evidence(effect, rec)
    with pytest.raises(TransitionError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            "attempt_id": effect["attempt_id"], "provider": effect["provider"],
            "receipt_id": rec["receipt_id"], "evidence": ev,
        })


def test_evidence_without_receipt_binding_is_rejected(tmp_path):
    effect = setup(tmp_path)
    rec = receipt(tmp_path, effect)
    ev = evidence(effect, rec, receipt_id=None)
    with pytest.raises(Exception):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            "attempt_id": effect["attempt_id"], "provider": effect["provider"],
            "receipt_id": rec["receipt_id"], "evidence": ev,
        })


def test_evidence_from_stale_attempt_cannot_satisfy_retry(tmp_path):
    effect = setup(tmp_path)
    rec1 = receipt(tmp_path, effect)
    from core.effect_authority import unknown, retry_dispatch
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "timeout")
    effect2 = retry_dispatch(str(tmp_path), effect["effect_id"], "agent-1",
                              f"{effect['effect_id']}:attempt:2", "provider-1", 2)
    ev1 = evidence(effect, rec1)
    with pytest.raises(Exception):
        observe(str(tmp_path), effect2["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            "attempt_id": effect2["attempt_id"], "provider": effect2["provider"],
            "receipt_id": rec1["receipt_id"], "evidence": ev1,
        })


def test_receipt_persistence_reloads_authoritative_effect(tmp_path):
    effect = setup(tmp_path)
    forged = dict(effect)
    forged["attempt_id"] = effect["effect_id"] + ":attempt:999"
    with pytest.raises(TransitionError, match="authoritative effect attempt"):
        persist_receipt(
            str(tmp_path), forged, forged["attempt_id"], effect["provider"],
            "op-forged", "OBSERVED_SUCCESS", {"status": "ok"},
        )
    assert not list((tmp_path / "receipts").glob("*.json"))


def test_receipt_persistence_rejects_terminal_authoritative_effect(tmp_path):
    effect = setup(tmp_path)
    from core.effect_authority import observe
    rec = receipt(tmp_path, effect)
    ev = evidence(effect, rec)
    observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
        "attempt_id": effect["attempt_id"], "provider": effect["provider"],
        "receipt_id": rec["receipt_id"], "evidence": ev,
    })
    with pytest.raises(TransitionError, match="currently DISPATCHED or UNKNOWN"):
        persist_receipt(
            str(tmp_path), effect, effect["attempt_id"], effect["provider"],
            "op-after-terminal", "OBSERVED_SUCCESS", {"status": "ok"},
        )


def accepted_observation(tmp_path):
    effect = setup(tmp_path)
    rec = receipt(tmp_path, effect)
    ev = evidence(effect, rec)
    observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
        "attempt_id": effect["attempt_id"], "provider": effect["provider"],
        "receipt_id": rec["receipt_id"], "evidence": ev,
    })
    return effect, rec, ev


def test_evaluation_requires_bound_accepted_lineage(tmp_path):
    effect, rec, ev = accepted_observation(tmp_path)
    before = json.loads((tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text())
    evaluation = evaluate(
        str(tmp_path), effect["effect_id"], effect["attempt_id"], rec["receipt_id"],
        ev, "grader", "1.0", "rubric-1", "PASS",
        components={"tests": {"passed": 1}},
        provenance={"source": "gate2-test"},
    )
    assert evaluation["effect_id"] == effect["effect_id"]
    assert evaluation["attempt_id"] == effect["attempt_id"]
    assert evaluation["receipt_id"] == rec["receipt_id"]
    assert evaluation["evidence_digest"] == ev["digest"]
    assert load_evaluation(str(tmp_path), evaluation["evaluation_id"]) == evaluation
    after = json.loads((tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text())
    assert after == before


def test_evaluation_rejects_missing_or_tampered_evidence(tmp_path):
    effect, rec, ev = accepted_observation(tmp_path)
    with pytest.raises(ValueError, match="valid evidence"):
        evaluate(str(tmp_path), effect["effect_id"], effect["attempt_id"],
                 rec["receipt_id"], {}, "grader", "1.0", "rubric-1", "PASS")
    tampered = dict(ev)
    tampered["claim"] = "forged"
    with pytest.raises(ValueError, match="valid evidence"):
        evaluate(str(tmp_path), effect["effect_id"], effect["attempt_id"],
                 rec["receipt_id"], tampered, "grader", "1.0", "rubric-1", "PASS")


def test_evaluation_rejects_wrong_receipt_or_stale_attempt(tmp_path):
    effect, rec, ev = accepted_observation(tmp_path)
    with pytest.raises(TransitionError, match="receipt binding"):
        evaluate(str(tmp_path), effect["effect_id"], effect["attempt_id"],
                 "RC-wrong", ev, "grader", "1.0", "rubric-1", "PASS")

    from core.effect_authority import unknown, retry_dispatch
    # Move a fresh effect through retry so the old attempt is no longer current.
    effect2 = setup(tmp_path / "second")
    rec2 = receipt(tmp_path / "second", effect2)
    ev2 = evidence(effect2, rec2)
    unknown(str(tmp_path / "second"), effect2["effect_id"], "agent-1", "timeout")
    retry_dispatch(str(tmp_path / "second"), effect2["effect_id"], "agent-1",
                   f"{effect2['effect_id']}:attempt:2", "provider-1", 2)
    with pytest.raises(TransitionError, match="accepted terminal observation"):
        evaluate(str(tmp_path / "second"), effect2["effect_id"], effect2["attempt_id"],
                 rec2["receipt_id"], ev2, "grader", "1.0", "rubric-1", "PASS")


def test_evaluation_is_derived_and_does_not_create_authority(tmp_path):
    effect, rec, ev = accepted_observation(tmp_path)
    before = json.loads((tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text())
    evaluate(str(tmp_path), effect["effect_id"], effect["attempt_id"], rec["receipt_id"],
             ev, "grader", "1.0", "rubric-1", "PASS")
    after = json.loads((tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text())
    assert after == before
    assert after["state"] == "OBSERVED_SUCCESS"


def test_evaluation_tamper_is_detected_on_reload(tmp_path):
    effect, rec, ev = accepted_observation(tmp_path)
    evaluation = evaluate(
        str(tmp_path), effect["effect_id"], effect["attempt_id"], rec["receipt_id"],
        ev, "grader", "1.0", "rubric-1", "PASS",
    )
    path = tmp_path / "evaluations" / (evaluation["evaluation_id"] + ".json")
    raw = json.loads(path.read_text())
    raw["verdict"] = "BLOCKED"
    path.write_text(json.dumps(raw))
    with pytest.raises(TransitionError, match="identity mismatch"):
        load_evaluation(str(tmp_path), evaluation["evaluation_id"])
