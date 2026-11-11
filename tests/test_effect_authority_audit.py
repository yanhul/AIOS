import json
import os

from core.effect_audit import audit_effect_authority


def test_effect_audit_detects_orphan_event_and_missing_terminal_receipt_without_mutation(tmp_path):
    state = tmp_path / ".aios"
    events = state / "events"
    effects = state / "effects"
    events.mkdir(parents=True)
    effects.mkdir()
    effect_id = "EF-" + "a" * 64
    effect = {
        "record_type": "EXTERNAL_EFFECT",
        "effect_id": effect_id,
        "contract_id": "contract-1",
        "logical_operation_id": "op-1",
        "permit_id": "permit-1",
        "actor": "test",
        "effect_type": "external_effect",
        "policy_digest": "sha256:" + "e" * 64,
        "max_attempts": 3,
        "provider": "gemini",
        "attempt": 1,
        "attempt_id": effect_id + ":attempt:1",
        "state": "OBSERVED_SUCCESS",
        "receipt_id": "RC-" + "b" * 64,
    }
    effect_path = effects / (effect_id + ".json")
    effect_path.write_text(json.dumps(effect), encoding="utf-8")
    event_path = events / "effect-orphan.json"
    event_path.write_text(json.dumps({
        "kind": "external_effect", "action": "dispatch",
        "effect_id": "EF-" + "c" * 64, "attempt": 1,
    }), encoding="utf-8")
    before = {p: p.read_bytes() for p in (effect_path, event_path)}

    findings = []
    audit_effect_authority(str(state), lambda check, severity, detail:
                           findings.append({"check": check, "severity": severity, "detail": detail}))

    checks = {item["check"] for item in findings}
    assert "effect_audit.effects.missing_receipt" in checks
    assert "effect_audit.events.orphan" in checks
    assert {p: p.read_bytes() for p in before} == before


def test_effect_audit_reports_invalid_claim_seal_and_missing_binding(tmp_path, monkeypatch):
    state = tmp_path / ".aios"
    claims = state / "execution_claims"
    claims.mkdir(parents=True)
    effect_id = "EF-" + "d" * 64
    path = claims / (effect_id + "-attempt-1.json")
    record = {
        "record_type": "EXECUTION_CLAIM",
        "kind": "execution_claim",
        "effect_id": effect_id,
        "attempt": 1,
        "attempt_id": effect_id + ":attempt:1",
        "provider": "gemini",
        "actor": "test",
        "seal": {"algorithm": "HMAC-SHA256", "key_id": "wrong", "mac": "0" * 64},
    }
    path.write_text(json.dumps(record), encoding="utf-8")
    findings = []
    audit_effect_authority(str(state), lambda check, severity, detail:
                           findings.append({"check": check, "severity": severity, "detail": detail}))
    checks = {item["check"] for item in findings}
    assert "effect_audit.seal.invalid_or_unverifiable" in checks
    assert "effect_audit.claims.orphan" in checks

def test_reconcile_routes_external_effect_events_to_wp1_without_m1_5_digest_rule(tmp_path):
    from core.reconcile import reconcile

    state = tmp_path / ".aios"
    effects = state / "effects"
    events = state / "events"
    effects.mkdir(parents=True)
    events.mkdir()
    from core.mutation import canonical_json
    import hashlib
    identity = {"contract_id": "contract-1", "logical_operation_id": "op-1", "actor": "test"}
    effect_id = "EF-" + hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    effect = {
        "record_type": "EXTERNAL_EFFECT",
        "effect_id": effect_id,
        "contract_id": "contract-1",
        "logical_operation_id": "op-1",
        "permit_id": "permit-1",
        "actor": "test",
        "effect_type": "external_effect",
        "policy_digest": "sha256:" + "e" * 64,
        "max_attempts": 2,
        "state": "PLANNED",
        "attempt": 0,
    }
    (effects / (effect_id + ".json")).write_text(json.dumps(effect), encoding="utf-8")
    (events / ("effect-create-" + effect_id + ".json")).write_text(json.dumps({
        "kind": "external_effect",
        "action": "create",
        "effect_id": effect_id,
        "contract_id": "contract-1",
        "permit_id": "permit-1",
        "effect_type": "external_effect",
        "state": "PLANNED",
        "actor": "test",
    }), encoding="utf-8")

    result = reconcile(str(state))
    checks = {finding["check"] for finding in result["findings"]}
    assert "D.event_digest" not in checks
    assert "G.unsupported_event" not in checks
    assert result["overall"] == "VALID"

def test_reconcile_accepts_real_sealed_receipt_claim_and_evaluation_lineage(tmp_path):
    from core.evaluation_plane import evaluate_persisted_receipt
    from core.reconcile import reconcile
    from tests.test_p1_receipt_load_binding_126 import _done

    aios, done = _done(tmp_path)
    evaluate_persisted_receipt(
        aios,
        done["receipt_id"],
        evaluator_version="audit-test-evaluator",
        rubric_version="audit-test-rubric",
        verdict="PASS",
        result={"reviewed": True},
    )
    result = reconcile(aios)
    assert result["overall"] == "VALID", result["findings"]


def test_wp1_detects_effect_identity_and_event_payload_tampering(tmp_path):
    from core.mutation import canonical_json
    import hashlib

    state = tmp_path / ".aios"
    effects = state / "effects"
    events = state / "events"
    effects.mkdir(parents=True)
    events.mkdir()
    identity = {"contract_id": "contract-1", "logical_operation_id": "op-1", "actor": "agent:test"}
    effect_id = "EF-" + hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    effect = {
        "record_type": "EXTERNAL_EFFECT", "effect_id": effect_id,
        "contract_id": "contract-1", "logical_operation_id": "op-1",
        "permit_id": "permit-1", "actor": "agent:test", "effect_type": "external_effect",
        "policy_digest": "sha256:" + "a" * 64, "max_attempts": 2,
        "state": "PLANNED", "attempt": 0,
    }
    (effects / (effect_id + ".json")).write_text(json.dumps(effect), encoding="utf-8")
    # A syntactically plausible create event with a conflicting permit is not a valid lineage edge.
    (events / ("effect-create-" + effect_id + ".json")).write_text(json.dumps({
        "kind": "external_effect", "action": "create", "effect_id": effect_id,
        "contract_id": "contract-1", "permit_id": "attacker-permit",
        "effect_type": "external_effect", "state": "PLANNED", "actor": "agent:test",
    }), encoding="utf-8")
    findings = []
    audit_effect_authority(str(state), lambda c, s, d: findings.append({"check": c, "severity": s, "detail": d}))
    checks = {item["check"] for item in findings}
    assert "effect_audit.events.binding" in checks


def test_wp1_detects_missing_create_event_and_invalid_dispatched_attempt(tmp_path):
    state = tmp_path / ".aios"
    effects = state / "effects"
    effects.mkdir(parents=True)
    effect_id = "EF-" + "9" * 64
    effect = {
        "record_type": "EXTERNAL_EFFECT", "effect_id": effect_id,
        "contract_id": "contract-1", "logical_operation_id": "op-1",
        "permit_id": "permit-1", "actor": "agent:test", "effect_type": "external_effect",
        "policy_digest": "sha256:" + "a" * 64, "max_attempts": 2,
        "state": "DISPATCHED", "attempt": 0, "attempt_id": effect_id + ":attempt:0",
        "provider": "gemini",
    }
    (effects / (effect_id + ".json")).write_text(json.dumps(effect), encoding="utf-8")
    findings = []
    audit_effect_authority(str(state), lambda c, s, d: findings.append({"check": c, "severity": s, "detail": d}))
    checks = {item["check"] for item in findings}
    assert "effect_audit.effects.identity" in checks
    assert "effect_audit.effects.attempt_binding" in checks
    assert "effect_audit.events.missing_create" in checks


def test_wp1_detects_reconciliation_evidence_attempt_mismatch(tmp_path):
    from core.evidence import EvidenceRecord

    state = tmp_path / ".aios"
    effects = state / "effects"
    recs = state / "reconciliations"
    effects.mkdir(parents=True)
    recs.mkdir()
    effect_id = "EF-" + "8" * 64
    effect = {
        "record_type": "EXTERNAL_EFFECT", "effect_id": effect_id,
        "contract_id": "contract-1", "logical_operation_id": "op-1",
        "permit_id": "permit-1", "actor": "agent:test", "effect_type": "external_effect",
        "policy_digest": "sha256:" + "a" * 64, "max_attempts": 2,
        "state": "UNKNOWN", "attempt": 1, "attempt_id": effect_id + ":attempt:1", "provider": "gemini",
    }
    (effects / (effect_id + ".json")).write_text(json.dumps(effect), encoding="utf-8")
    evidence = EvidenceRecord("EV-wrong", "OBSERVED", "provider://gemini/status", "not applied",
                              effect_id + ":attempt:2", "gemini").as_record()
    rec = {
        "record_type": "EFFECT_RECONCILIATION", "effect_id": effect_id, "attempt": 1,
        "attempt_id": effect_id + ":attempt:1", "contract_id": "contract-1", "provider": "gemini",
        "verdict": "INCONCLUSIVE", "evidence": evidence, "actor": "agent:test",
        "outcome": None, "attestation": None, "source_authenticity": {"level": "UNSIGNED"},
    }
    (recs / (effect_id + "-attempt-1.json")).write_text(json.dumps(rec), encoding="utf-8")
    findings = []
    audit_effect_authority(str(state), lambda c, s, d: findings.append({"check": c, "severity": s, "detail": d}))
    checks = {item["check"] for item in findings}
    assert "effect_audit.reconciliations.evidence_binding" in checks
