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
    effect_id = "EF-" + "f" * 64
    effect = {
        "record_type": "EXTERNAL_EFFECT",
        "effect_id": effect_id,
        "contract_id": "contract-1",
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
