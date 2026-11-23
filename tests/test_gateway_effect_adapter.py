import json

import pytest

from core.attestation import issue_attestation
from core.authority import load_permit, persist_attestation, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity, issue_permit
from core.effect_authority import create_effect, dispatch, retry_dispatch, unknown
from core.gateway_effect_adapter import build_gateway_effect_contract
from core.policy_registry import persist_policy

SECRET = "test-secret"


def _authority(tmp_path):
    registry = CapabilityRegistry()
    registry.register(Capability("try.research", "1", "test", "research", status="ACTIVE"))
    registry.persist(str(tmp_path), "test")
    policy = persist_policy(str(tmp_path), {"policy_type": "GOVERNING_POLICY", "name": "gateway-test"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "task-1", "scope": "try",
        "actor": "aios", "capabilities": ["try.research@1"],
        "input_digest": "sha256:input", "allowed_effects": ["run_research"],
        "evidence_required": ["experiment_ledger"], "max_attempts": 2,
        "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"], "policy_digest": policy,
    }
    stored = persist_contract(str(tmp_path), contract)
    permit = persist_permit(str(tmp_path), stored, "AIOS_AUTHORITY")
    attestation = persist_attestation(str(tmp_path), stored, permit, SECRET)
    effect = create_effect(str(tmp_path), contract_identity(contract), "op-1", "aios", permit["permit_id"], "run_research")
    return contract, permit, attestation, effect


def _build(tmp_path, contract, permit, attestation, effect, **overrides):
    args = {
        "aios_dir": str(tmp_path), "persisted_effect": effect,
        "effect_id": effect["effect_id"], "action": "run_research",
        "capability_ref": "try.research@1", "authority_ref": permit["permit_id"],
        "authority_permit": permit, "authority_attestation": attestation,
        "attestation_secret": SECRET, "evidence_ref": "EV-1",
        "lineage_ref": "LIN-1", "idempotency_key": "idem-1",
    }
    args.update(overrides)
    return build_gateway_effect_contract(contract, **args)


def test_builds_gateway_v3_contract_from_current_persisted_authority(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    result = _build(tmp_path, contract, permit, attestation, effect)
    assert result["protocol_version"] == 4
    assert result["effect_id"] == effect["effect_id"]
    assert result["authority_ref"] == permit["permit_id"]


def test_stale_permit_is_rejected(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    stale = dict(permit, permit_id="PT-stale")
    with pytest.raises(ValueError):
        _build(tmp_path, contract, stale, attestation, effect, authority_ref="PT-stale")


def test_stale_attestation_is_rejected(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    stale = issue_attestation(contract, issue_permit(contract, "OLD_AUTHORITY"), SECRET)
    with pytest.raises(ValueError, match="attestation"):
        _build(tmp_path, contract, permit, stale, effect)


def test_revoked_capability_is_rejected_at_gateway_crossing(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    registry = CapabilityRegistry()
    registry.register(Capability("try.research", "1", "test", "research", status="DEPRECATED"))
    registry.persist(str(tmp_path), "revoker")
    with pytest.raises(Exception):
        _build(tmp_path, contract, permit, attestation, effect)


def test_changed_policy_artifact_is_rejected_fail_closed(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    path = tmp_path / "policies" / f"{contract['policy_digest']}.json"
    data = json.loads(path.read_text())
    data["name"] = "changed-policy"
    path.write_text(json.dumps(data))
    with pytest.raises(Exception):
        _build(tmp_path, contract, permit, attestation, effect)


def test_permit_a_cannot_cross_effect_b(tmp_path):
    contract, permit_a, attestation_a, _effect_a = _authority(tmp_path)
    permit_b = persist_permit(str(tmp_path), contract, "SECOND_AUTHORITY")
    attestation_b = persist_attestation(str(tmp_path), contract, permit_b, SECRET)
    effect_b = create_effect(str(tmp_path), contract_identity(contract), "op-2", "aios", permit_b["permit_id"], "run_research")
    with pytest.raises(ValueError, match="persisted effect permit"):
        _build(tmp_path, contract, permit_a, attestation_a, effect_b)
    assert attestation_b["permit_id"] == permit_b["permit_id"]


def test_contract_a_cannot_cross_effect_b(tmp_path):
    contract_a, _permit_a, _attestation_a, _effect_a = _authority(tmp_path)
    contract_b = dict(contract_a, task_id="task-2", input_digest="sha256:other")
    stored_b = persist_contract(str(tmp_path), contract_b)
    permit_b = persist_permit(str(tmp_path), stored_b, "AIOS_AUTHORITY")
    attestation_b = persist_attestation(str(tmp_path), stored_b, permit_b, SECRET)
    effect_b = create_effect(str(tmp_path), contract_identity(contract_b), "op-2", "aios", permit_b["permit_id"], "run_research")
    with pytest.raises(ValueError, match="workload contract"):
        _build(tmp_path, contract_a, permit_b, attestation_b, effect_b)


def test_forged_authority_ref_and_effect_binding_are_rejected(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    with pytest.raises(ValueError, match="persisted effect permit"):
        _build(tmp_path, contract, permit, attestation, effect, authority_ref="PT-forged")
    forged = dict(effect, effect_id="effect-forged")
    with pytest.raises(KeyError, match="unknown effect"):
        _build(tmp_path, contract, permit, attestation, forged)


def test_load_permit_fails_closed_on_malformed_or_mismatched_record(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    path = tmp_path / "authority" / "permits" / f"{permit['permit_id']}.json"
    data = json.loads(path.read_text())
    data.pop("issuer")
    path.write_text(json.dumps(data))
    with pytest.raises(Exception, match="malformed"):
        load_permit(str(tmp_path), permit["permit_id"])


def test_retry_after_capability_authority_change_is_rejected(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    dispatched = dispatch(
        str(tmp_path), effect["effect_id"], "aios", f"{effect['effect_id']}:attempt:1", "try.research",
        target_sha="sha256:target", evidence_ref="EV-1", lineage_ref="LIN-1",
        idempotency_key="idem-1", attempt_fence=1,
    )
    unknown(str(tmp_path), effect["effect_id"], "aios", "provider timeout")
    registry = CapabilityRegistry()
    registry.register(Capability("try.research", "1", "test", "research", status="DEPRECATED"))
    registry.persist(str(tmp_path), "revoker")
    with pytest.raises(Exception):
        retry_dispatch(
            str(tmp_path), effect["effect_id"], "aios", f"{effect['effect_id']}:attempt:2", "try.research", 2,
            target_sha="sha256:target", attempt_fence=2,
        )
    assert dispatched["attempt"] == 1


def test_missing_or_undeclared_capability_and_effect_remain_fail_closed(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    with pytest.raises(ValueError, match="not granted"):
        _build(tmp_path, contract, permit, attestation, effect, capability_ref="try.research@2")
    with pytest.raises(ValueError, match="(not allowed|does not match persisted effect)"):
        _build(tmp_path, contract, permit, attestation, effect, action="push_to_github")


def test_gateway_v4_cli_restart_replay_and_unknown_receipt(tmp_path, monkeypatch):
    import os
    from pathlib import Path
    from core.gateway_effect_adapter import GatewayCLITransport

    cli = os.environ.get("HARNESS_GATEWAY_CLI")
    if not cli:
        pytest.skip("HARNESS_GATEWAY_CLI is only configured in cross-repository CI")
    governance = {key: "sha256:" + key for key in (
        "policy", "evidence_criteria", "promotion_criteria",
        "terminal_conditions", "trust_roots",
    )}
    # A new transport instance per operation simulates process restart.
    def client():
        return GatewayCLITransport(
            cli_path=cli, state_path=tmp_path / "gateway-state.json",
            human_identity="human:test", governance=governance,
        )

    contract = {
        "protocol_version": 4, "effect_id": "EF-CROSS-1",
        "action": "run_research", "capability_ref": "try.research@1",
        "authority_ref": "PT-AIOS-1", "evidence_ref": "EV-PRE-1",
        "lineage_ref": "LIN-1", "idempotency_key": "idem-cross-1",
    }
    client().create_ticket(
        ticket="T-CROSS-1", repository="yanhul/AIOS", target_sha="sha256:target",
        nonce="nonce-cross-1", ttl_seconds=300, effect_contract=contract,
    )
    client().authorize(ticket="T-CROSS-1", nonce="nonce-cross-1",
                       sender="human:test", target_sha="sha256:target")
    first = client().begin_effect(ticket="T-CROSS-1", target_sha="sha256:target")
    replay = client().begin_effect(ticket="T-CROSS-1", target_sha="sha256:target")
    assert first["execute_allowed"] is True
    assert replay["replayed"] is True
    assert replay["execute_allowed"] is False
    receipt = {
        "ticket_id": "T-CROSS-1", "attempt_id": first["attempt_id"],
        "attempt_fence": first["fence"], "target_sha": "sha256:target", "effect_id": "EF-CROSS-1",
        "status": "UNKNOWN", "evidence_ref": "EV-PRE-1",
        "lineage_ref": "LIN-1",
    }
    client().record_receipt(ticket="T-CROSS-1", receipt=receipt)
    status = client().status()
    saved = status["tickets"]["T-CROSS-1"]
    assert saved["attempts"] == 1
    assert saved["attempt_history"][0]["status"] == "UNKNOWN"
    assert len(saved["receipt_history"]) == 1
    assert saved["state"] == "AUTHORIZED"


def test_gateway_transport_rejects_non_v4_contract_before_io(tmp_path):
    from core.gateway_effect_adapter import GatewayCLITransport, GatewayTransportError
    client = GatewayCLITransport(
        cli_path="missing-gateway-cli.py", state_path=tmp_path / "state.json",
        human_identity="human:test", governance={key: key for key in (
            "policy", "evidence_criteria", "promotion_criteria",
            "terminal_conditions", "trust_roots",
        )},
    )
    with pytest.raises(GatewayTransportError, match="protocol_version must be 4"):
        client.create_ticket(ticket="T", repository="r", target_sha="s",
                             nonce="n", ttl_seconds=10,
                             effect_contract={"protocol_version": 3})
