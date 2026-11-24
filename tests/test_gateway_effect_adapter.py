import json

import pytest

from core.attestation import issue_attestation
from core.authority import load_permit, persist_attestation, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity, issue_permit
from core.effect_authority import (
    create_effect, dispatch, retry_dispatch, unknown, bind_try_operation_request,
)
from core.gateway_effect_adapter import (
    GatewayTransportError, begin_and_dispatch_aios_effect, build_gateway_effect_contract,
    record_gateway_receipt, prepare_gateway_retry_permit, retry_gateway_effect,
)
from core.gateway_retry_permit import GatewayRetryPermitSigner
from core.try_operation_receipt import TryOperationReceiptKeyring, SIGNED_FIELDS
from tests.try_operation_receipt_fixtures import PUBLIC_KEY_B64, sign_receipt
from tests.retry_issuers import KEYRING as RETRY_KEYRING, ISSUER_SECRETS
from core.policy_registry import persist_policy

SECRET = "unit-test-authority-secret-32"


def _authority(tmp_path):
    import os
    os.environ["AIOS_AUTHORITY_ATTESTATION_SECRET"] = SECRET
    registry = CapabilityRegistry()
    registry.register(Capability("try.research", "1", "test", "research", status="ACTIVE"))
    registry.register(Capability("try.repair", "1", "test", "repair", status="ACTIVE"))
    registry.persist(str(tmp_path), "test")
    policy = persist_policy(str(tmp_path), {"policy_type": "GOVERNING_POLICY", "name": "gateway-test"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "task-1", "scope": "try",
        "actor": "aios", "capabilities": ["try.research@1", "try.repair@1"],
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


def test_builds_gateway_v5_contract_from_current_persisted_authority(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    result = _build(tmp_path, contract, permit, attestation, effect)
    assert result["protocol_version"] == 5
    assert result["contract_id"] == contract_identity(contract)
    assert result["actor"] == "aios"
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
    path = tmp_path / "policies" / f"{contract['policy_digest'].removeprefix('sha256:')}.json"
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
    with pytest.raises(Exception):
        _build(tmp_path, contract, permit, attestation, effect)


def test_retry_after_capability_authority_change_is_rejected(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    dispatched = dispatch(
        str(tmp_path), effect["effect_id"], "aios", f"{effect['effect_id']}:attempt:1", "try.research",
        target_sha="sha256:target", evidence_ref="EV-1", lineage_ref="LIN-1",
        idempotency_key="idem-1", attempt_fence=1,
        gateway_attempt_id="TICKET-CAPABILITY:1",
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


def test_gateway_v5_cli_restart_replay_and_unknown_receipt(tmp_path, monkeypatch):
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
        "protocol_version": 5, "effect_id": "EF-CROSS-1", "contract_id": "C-CROSS-1", "actor": "aios",
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


def test_gateway_transport_rejects_non_v5_contract_before_io(tmp_path):
    from core.gateway_effect_adapter import GatewayCLITransport, GatewayTransportError
    client = GatewayCLITransport(
        cli_path="missing-gateway-cli.py", state_path=tmp_path / "state.json",
        human_identity="human:test", governance={key: key for key in (
            "policy", "evidence_criteria", "promotion_criteria",
            "terminal_conditions", "trust_roots",
        )},
    )
    with pytest.raises(GatewayTransportError, match="protocol_version must be 5"):
        client.create_ticket(ticket="T", repository="r", target_sha="s",
                             nonce="n", ttl_seconds=10,
                             effect_contract={"protocol_version": 3})


class _FakeGateway:
    def __init__(self, response):
        self.response = response
        self.calls = 0

    def begin_effect(self, *, ticket, target_sha):
        self.calls += 1
        return dict(self.response)


def test_gateway_attempt_is_mapped_to_distinct_aios_and_gateway_ids(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    gateway = _FakeGateway({
        "attempt_id": "TICKET-1:1", "attempt_number": 1, "fence": 7,
        "effect_id": effect["effect_id"], "idempotency_key": "idem-1",
        "target_sha": "sha256:target", "ticket_id": "TICKET-1",
        "execute_allowed": True, "replayed": False,
    })
    result = begin_and_dispatch_aios_effect(
        gateway, ticket="TICKET-1", target_sha="sha256:target",
        aios_dir=str(tmp_path), effect=effect, actor="aios",
        provider="try.research", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1",
    )
    assert result["execute_allowed"] is True
    assert result["aios_attempt_id"] == effect["effect_id"] + ":attempt:1"
    assert result["gateway_attempt_id"] == "TICKET-1:1"
    assert result["effect"]["attempt_id"] == result["aios_attempt_id"]
    assert result["effect"]["gateway_attempt_id"] == "TICKET-1:1"
    assert result["effect"]["attempt_fence"] == 7
    assert result["effect"]["state"] == "DISPATCHED"
    assert gateway.calls == 1


def test_gateway_replay_maps_orphaned_attempt_to_unknown_without_execution(tmp_path):
    _contract, _permit, _attestation, effect = _authority(tmp_path)
    gateway = _FakeGateway({
        "attempt_id": "TICKET-1:1", "attempt_number": 1, "fence": 7,
        "effect_id": effect["effect_id"], "idempotency_key": "idem-1",
        "target_sha": "sha256:target", "ticket_id": "TICKET-1",
        "execute_allowed": False, "replayed": True,
    })
    result = begin_and_dispatch_aios_effect(
        gateway, ticket="TICKET-1", target_sha="sha256:target",
        aios_dir=str(tmp_path), effect=effect, actor="aios",
        provider="try.research", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1",
    )
    assert result["execute_allowed"] is False
    assert result["reconciliation"] == "REPLAYED_ATTEMPT_RECORDED_UNKNOWN"
    saved = json.loads((tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text())
    assert saved["state"] == "UNKNOWN"
    assert saved["attempt"] == 1
    assert saved["gateway_attempt_id"] == "TICKET-1:1"


def test_gateway_invalid_fence_never_dispatches_aios(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    gateway = _FakeGateway({
        "attempt_id": "TICKET-1:1", "fence": True,
        "execute_allowed": True, "replayed": False,
    })
    with pytest.raises(GatewayTransportError, match="invalid attempt fence"):
        begin_and_dispatch_aios_effect(
            gateway, ticket="TICKET-1", target_sha="sha256:target",
            aios_dir=str(tmp_path), effect=effect, actor="aios",
            provider="try.research", evidence_ref="EV-1",
            lineage_ref="LIN-1", idempotency_key="idem-1",
        )
    saved = json.loads((tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text())
    assert saved["state"] == "PLANNED"


def test_real_gateway_cli_to_aios_effect_mapping_survives_replay(tmp_path, monkeypatch):
    import os
    from core.gateway_effect_adapter import GatewayCLITransport

    cli = os.environ.get("HARNESS_GATEWAY_CLI")
    if not cli:
        pytest.skip("HARNESS_GATEWAY_CLI is only configured in cross-repository CI")
    contract, permit, attestation, effect = _authority(tmp_path)
    governance = {key: "sha256:" + key for key in (
        "policy", "evidence_criteria", "promotion_criteria",
        "terminal_conditions", "trust_roots",
    )}
    transport = GatewayCLITransport(
        cli_path=cli, state_path=tmp_path / "gateway-state.json",
        human_identity="human:test", governance=governance,
    )
    gateway_contract = _build(tmp_path, contract, permit, attestation, effect)
    transport.create_ticket(
        ticket="T-AIOS-BRIDGE", repository="yanhul/AIOS",
        target_sha="sha256:target", nonce="nonce-aios-bridge",
        ttl_seconds=300, effect_contract=gateway_contract,
    )
    transport.authorize(
        ticket="T-AIOS-BRIDGE", nonce="nonce-aios-bridge",
        sender="human:test", target_sha="sha256:target",
    )
    result = begin_and_dispatch_aios_effect(
        transport, ticket="T-AIOS-BRIDGE", target_sha="sha256:target",
        aios_dir=str(tmp_path), effect=effect, actor="aios",
        provider="try.research", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1",
    )
    assert result["execute_allowed"] is True
    assert result["effect"]["state"] == "DISPATCHED"
    assert result["effect"]["attempt_id"] == effect["effect_id"] + ":attempt:1"
    assert result["effect"]["gateway_attempt_id"] != result["effect"]["attempt_id"]
    assert result["effect"]["attempt_fence"] >= 1

    # Simulate a caller restart with its stale PLANNED snapshot. Gateway's
    # durable replay fence must refuse a second execution before AIOS mutation.
    replay = begin_and_dispatch_aios_effect(
        transport, ticket="T-AIOS-BRIDGE", target_sha="sha256:target",
        aios_dir=str(tmp_path), effect=effect, actor="aios",
        provider="try.research", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1",
    )
    assert replay["execute_allowed"] is False
    assert replay["effect"]["state"] == "UNKNOWN"

    receipt = {
        "ticket_id": "T-AIOS-BRIDGE",
        "attempt_id": result["gateway_attempt_id"],
        "attempt_fence": result["attempt_fence"],
        "target_sha": "sha256:target", "effect_id": effect["effect_id"],
        "status": "UNKNOWN", "evidence_ref": "EV-1", "lineage_ref": "LIN-1",
    }
    reconciled = record_gateway_receipt(
        transport, ticket="T-AIOS-BRIDGE", aios_dir=str(tmp_path),
        effect_id=effect["effect_id"], actor="aios", receipt=receipt,
    )
    assert reconciled["reconciliation"] == "ALREADY_UNKNOWN"
    assert reconciled["aios_effect"]["state"] == "UNKNOWN"

    from tests.provider_keys import sign_observation
    completed_receipt = dict(receipt, status="COMPLETED")
    signed = sign_observation(
        result["effect"], {
            "provider": "try.research", "provider_operation_id": "provider-op-1",
            "effect_id": effect["effect_id"], "attempt_id": result["aios_attempt_id"],
            "observation": {"status": "completed", "result_ref": "artifact:gateway-result"},
        },
    )
    provider_observation = {
        **signed, "gateway_attempt_id": result["gateway_attempt_id"],
        "target_sha": "sha256:target", "evidence_ref": "EV-1",
        "lineage_ref": "LIN-1", "idempotency_key": "idem-1",
        "attempt_fence": result["attempt_fence"],
    }
    completed = record_gateway_receipt(
        transport, ticket="T-AIOS-BRIDGE", aios_dir=str(tmp_path),
        effect_id=effect["effect_id"], actor="aios", receipt=completed_receipt,
        provider_observation=provider_observation,
    )
    assert completed["reconciliation"] == "RECONCILED"
    assert completed["aios_effect"]["state"] == "OBSERVED_SUCCESS"

    saved = json.loads((tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text())
    assert saved["state"] == "OBSERVED_SUCCESS"
    assert saved["attempt"] == 1
    assert saved["gateway_attempt_id"] == result["gateway_attempt_id"]


def test_gateway_unknown_receipt_is_persisted_then_reconciled_to_aios_unknown(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    from core.effect_authority import dispatch
    dispatched = dispatch(
        str(tmp_path), effect["effect_id"], "aios", effect["effect_id"] + ":attempt:1",
        "try.research", target_sha="sha256:target", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1", attempt_fence=7,
        gateway_attempt_id="TICKET-UNKNOWN:1",
    )
    class Transport:
        def __init__(self): self.saved = None
        def record_receipt(self, *, ticket, receipt):
            self.saved = dict(receipt)
            return {"ticket_id": ticket, "receipt_history": [self.saved]}
    transport = Transport()
    receipt = {
        "ticket_id": "TICKET-UNKNOWN", "attempt_id": "TICKET-UNKNOWN:1",
        "attempt_fence": 7, "target_sha": "sha256:target",
        "effect_id": effect["effect_id"], "status": "UNKNOWN",
        "evidence_ref": "EV-1", "lineage_ref": "LIN-1",
    }
    result = record_gateway_receipt(
        transport, ticket="TICKET-UNKNOWN", aios_dir=str(tmp_path),
        effect_id=effect["effect_id"], actor="aios", receipt=receipt,
    )
    assert transport.saved == receipt
    assert result["reconciliation"] == "UNKNOWN_RECORDED"
    assert result["aios_effect"]["state"] == "UNKNOWN"


def test_terminal_gateway_receipt_without_aios_evidence_stays_unresolved(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    from core.effect_authority import dispatch
    dispatched = dispatch(
        str(tmp_path), effect["effect_id"], "aios", effect["effect_id"] + ":attempt:1",
        "try.research", target_sha="sha256:target", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1", attempt_fence=7,
        gateway_attempt_id="TICKET-TERMINAL:1",
    )
    class Transport:
        def record_receipt(self, *, ticket, receipt): return {"ticket_id": ticket, "saved": True}
    receipt = {
        "ticket_id": "TICKET-TERMINAL", "attempt_id": "TICKET-TERMINAL:1",
        "attempt_fence": 7, "target_sha": "sha256:target",
        "effect_id": effect["effect_id"], "status": "COMPLETED",
        "evidence_ref": "EV-1", "lineage_ref": "LIN-1",
    }
    result = record_gateway_receipt(
        Transport(), ticket="TICKET-TERMINAL", aios_dir=str(tmp_path),
        effect_id=effect["effect_id"], actor="aios", receipt=receipt,
    )
    assert result["reconciliation"] == "PENDING_AIOS_EVIDENCE"
    assert result["aios_effect"]["state"] == "DISPATCHED"


def test_provider_receipt_must_bind_gateway_attempt_identity():
    from core.runtime import ProviderReceipt, validate_receipt
    effect = {
        "effect_id": "EF-1", "attempt_id": "EF-1:attempt:1",
        "target_sha": "sha256:target", "attempt_fence": 7,
        "gateway_attempt_id": "T-1:1", "evidence_ref": "EV-1",
        "lineage_ref": "LIN-1", "idempotency_key": "idem-1",
    }
    base = dict(
        provider="try.research", effect_id="EF-1",
        attempt_id="EF-1:attempt:1", provider_operation_id="op-1",
        outcome="OBSERVED_SUCCESS",
        observation={"evidence": {"evidence_id": "EV-1"}},
        target_sha="sha256:target", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1", attempt_fence=7,
        gateway_attempt_id="T-1:1",
    )
    validate_receipt(ProviderReceipt(**base), effect, "EF-1:attempt:1", "try.research")
    base["gateway_attempt_id"] = "T-OTHER:1"
    with pytest.raises(ValueError, match="gateway_attempt_id binding mismatch"):
        validate_receipt(ProviderReceipt(**base), effect, "EF-1:attempt:1", "try.research")


def test_gateway_backed_unknown_effect_cannot_bypass_gateway_for_retry(tmp_path):
    from core.effect_authority import dispatch, retry_dispatch, unknown
    contract, permit, attestation, effect = _authority(tmp_path)
    dispatch(
        str(tmp_path), effect["effect_id"], "aios", effect["effect_id"] + ":attempt:1",
        "try.research", target_sha="sha256:target", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1", attempt_fence=7,
        gateway_attempt_id="TICKET-RETRY:1",
    )
    unknown(str(tmp_path), effect["effect_id"], "aios", "provider outcome unknown")
    with pytest.raises(Exception, match="Gateway-backed retry is blocked"):
        retry_dispatch(
            str(tmp_path), effect["effect_id"], "aios",
            effect["effect_id"] + ":attempt:2", "try.research", 2,
        )

def test_late_signed_gateway_receipt_reconciles_only_same_unknown_attempt(tmp_path):
    from tests.provider_keys import sign_observation
    from core.effect_authority import dispatch, unknown

    _contract, _permit, _attestation, effect = _authority(tmp_path)
    dispatched = dispatch(
        str(tmp_path), effect["effect_id"], "aios", effect["effect_id"] + ":attempt:1",
        "try.research", target_sha="sha256:target", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1", attempt_fence=7,
        gateway_attempt_id="TICKET-LATE:1",
    )
    unknown(str(tmp_path), effect["effect_id"], "aios", "worker disconnected after dispatch")

    class Transport:
        def record_receipt(self, *, ticket, receipt):
            return {"ticket_id": ticket, "receipt_history": [dict(receipt)]}

    gateway_receipt = {
        "ticket_id": "TICKET-LATE", "attempt_id": "TICKET-LATE:1",
        "attempt_fence": 7, "target_sha": "sha256:target",
        "effect_id": effect["effect_id"], "status": "COMPLETED",
        "evidence_ref": "EV-1", "lineage_ref": "LIN-1",
    }
    signed = sign_observation(dispatched, {
        "provider": "try.research", "provider_operation_id": "op-late-1",
        "effect_id": effect["effect_id"], "attempt_id": dispatched["attempt_id"],
        "observation": {"status": "completed", "artifact": "result.json"},
    })
    provider_observation = {**signed, "gateway_attempt_id": "TICKET-LATE:1"}
    result = record_gateway_receipt(
        Transport(), ticket="TICKET-LATE", aios_dir=str(tmp_path),
        effect_id=effect["effect_id"], actor="aios", receipt=gateway_receipt,
        provider_observation=provider_observation,
    )
    assert result["reconciliation"] == "RECONCILED"
    assert result["aios_effect"]["state"] == "OBSERVED_SUCCESS"
    assert result["aios_effect"]["gateway_attempt_id"] == "TICKET-LATE:1"


def test_partial_gateway_attempt_binding_is_rejected_on_reload(tmp_path):
    _contract, _permit, _attestation, effect = _authority(tmp_path)
    dispatch(
        str(tmp_path), effect["effect_id"], "aios", effect["effect_id"] + ":attempt:1",
        "try.research", target_sha="sha256:target", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1", attempt_fence=7,
        gateway_attempt_id="TICKET-PARTIAL:1",
    )
    path = tmp_path / "effects" / f"{effect['effect_id']}.json"
    saved = json.loads(path.read_text())
    saved.pop("gateway_attempt_id")
    path.write_text(json.dumps(saved))
    from core.effect_authority import unknown
    with pytest.raises(Exception, match="Gateway attempt binding is incomplete"):
        unknown(str(tmp_path), effect["effect_id"], "aios", "tampered")


class _FakeGatewayRetryTransport:
    def __init__(self, *, ticket_state, retry_response=None):
        self.ticket_state = ticket_state
        self.retry_response = retry_response
        self.retry_calls = 0
    def status(self):
        return {"tickets": {"T-RETRY": self.ticket_state}}
    def retry_effect(self, *, ticket, retry_permit):
        self.retry_calls += 1
        return dict(self.retry_response)


def _try_receipt_keyring():
    spec = {"try.repair": {"key_id": "try-op-test-v1", "public_key": PUBLIC_KEY_B64,
                           "scopes": ["try.operation.receipt.verify"], "revoked": False}}
    return TryOperationReceiptKeyring(spec)


def _signed_try_preflight_receipt(*, request_id, request_digest, repository, sha, attempt, now):
    import hashlib, json
    body = {
        "type": "TRY_PROPOSAL_OPERATION_RECEIPT_V1", "issuer": "try.repair",
        "key_id": "try-op-test-v1", "receipt_id": "TR-" + "b" * 32,
        "request_id": request_id, "request_digest": request_digest,
        "repository": repository, "sha": sha, "attempt": attempt,
        "status": "FAILED", "execution_state": "NOT_SUBMITTED",
        "failure_code": "provider_not_configured", "proposal_digest": None,
        "issued_at": now, "expires_at": now + 300, "algorithm": "Ed25519",
    }
    return sign_receipt(body, SIGNED_FIELDS)


def _gateway_retry_fixture(tmp_path, now=1000.0):
    contract, permit, attestation, effect = _authority(tmp_path)
    target_sha = "a" * 40
    dispatched = dispatch(
        str(tmp_path), effect["effect_id"], "aios", effect["effect_id"] + ":attempt:1", "try.repair",
        target_sha=target_sha, evidence_ref="EV-1", lineage_ref="LIN-1",
        idempotency_key="idem-1", attempt_fence=1, gateway_attempt_id="T-RETRY:1",
    )
    request_body = {"request_id": dispatched["attempt_id"], "repository": "yanhul/AIOS",
                    "sha": target_sha, "attempt": 1, "failure": {}, "source_snapshot": {"core/a.py": "x"}}
    from core.try_repair_provider import _request_digest
    request_digest = _request_digest(request_body)
    bind_try_operation_request(
        str(tmp_path), effect["effect_id"], "aios", request_id=dispatched["attempt_id"],
        request_digest=request_digest, repository="yanhul/AIOS", sha=target_sha,
    )
    unknown(str(tmp_path), effect["effect_id"], "aios", "TRY preflight result needs trusted reconciliation")
    gateway_receipt = {
        "ticket_id": "T-RETRY", "attempt_id": "T-RETRY:1", "attempt_fence": 1,
        "target_sha": target_sha, "effect_id": effect["effect_id"], "status": "UNKNOWN",
        "evidence_ref": "EV-1", "lineage_ref": "LIN-1",
    }
    import hashlib, json
    receipt_digest = hashlib.sha256(json.dumps(gateway_receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    ticket_state = {
        "state": "AUTHORIZED", "repository": "yanhul/AIOS", "target_sha": target_sha, "attempts": 1,
        "effect_contract": {"effect_id": effect["effect_id"], "contract_id": contract_identity(contract),
                            "actor": "aios", "authority_ref": permit["permit_id"], "action": "run_research",
                            "capability_ref": "try.repair@1",
                            "evidence_ref": "EV-1", "lineage_ref": "LIN-1", "idempotency_key": "idem-1"},
        "attempt_history": [{"attempt_id": "T-RETRY:1", "attempt_number": 1, "fence": 1, "status": "UNKNOWN"}],
        "receipt_history": [{"receipt": gateway_receipt, "digest": receipt_digest}],
    }
    return contract, permit, effect, dispatched, request_digest, receipt_digest, ticket_state


def test_try_preflight_receipt_issues_signed_retry_permit_and_maps_gateway_fence(tmp_path):
    import time
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    contract, permit, effect, dispatched, request_digest, receipt_digest, ticket_state = _gateway_retry_fixture(tmp_path)
    now = time.time()
    operation_keyring = _try_receipt_keyring()
    receipt = _signed_try_preflight_receipt(
        request_id=dispatched["attempt_id"], request_digest=request_digest,
        repository="yanhul/AIOS", sha="a" * 40, attempt=1, now=now,
    )
    private = Ed25519PrivateKey.generate()
    signer = GatewayRetryPermitSigner(private)
    transport = _FakeGatewayRetryTransport(ticket_state=ticket_state)
    permit_record = prepare_gateway_retry_permit(
        transport, ticket="T-RETRY", aios_dir=str(tmp_path), effect_id=effect["effect_id"], actor="aios",
        operation_receipt=receipt, issuer="operator:test", reason="TRY preflight proved no Gemini submission",
        issuer_secret=ISSUER_SECRETS["operator:test"], retry_keyring=RETRY_KEYRING,
        signer=signer, operation_keyring=operation_keyring, now=now,
    )
    assert signer.verify(permit_record)
    assert permit_record["reconciliation_outcome"] == "PROVEN_NOT_SUBMITTED"
    assert permit_record["prior_gateway_receipt_digest"] == receipt_digest
    assert permit_record["next_fence"] == 2
    assert (tmp_path / "gateway_retry_permits" / f"{permit_record['permit_id']}.evidence.json").exists()
    response = {
        **ticket_state["effect_contract"], "ticket_id": "T-RETRY", "attempt_id": "T-RETRY:2",
        "attempt_number": 2, "fence": 2, "target_sha": "a" * 40,
        "retry_permit_id": permit_record["permit_id"], "replayed": False, "execute_allowed": True,
    }
    transport.retry_response = response
    result = retry_gateway_effect(
        transport, ticket="T-RETRY", aios_dir=str(tmp_path), effect_id=effect["effect_id"],
        actor="aios", provider="try.repair", retry_permit=permit_record, signer=signer,
        retry_keyring=RETRY_KEYRING, now=now,
    )
    assert result["execute_allowed"] is True
    assert result["attempt_fence"] == 2
    assert result["effect"]["state"] == "DISPATCHED"
    assert result["effect"]["attempt"] == 2
    assert result["effect"]["gateway_attempt_id"] == "T-RETRY:2"
    assert (tmp_path / "gateway_retry_permits" / f"{permit_record['permit_id']}.consumed.json").exists()
    calls_before = transport.retry_calls
    with pytest.raises(GatewayTransportError, match="current UNKNOWN effect"):
        retry_gateway_effect(
            transport, ticket="T-RETRY", aios_dir=str(tmp_path), effect_id=effect["effect_id"], actor="aios",
            provider="try.repair", retry_permit=permit_record, signer=signer,
            retry_keyring=RETRY_KEYRING, now=now,
        )
    assert transport.retry_calls == calls_before


def test_unknown_try_operation_receipt_cannot_issue_gateway_retry_permit(tmp_path):
    import time
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    contract, permit, effect, dispatched, request_digest, _receipt_digest, ticket_state = _gateway_retry_fixture(tmp_path)
    now = time.time()
    operation_keyring = _try_receipt_keyring()
    receipt = _signed_try_preflight_receipt(
        request_id=dispatched["attempt_id"], request_digest=request_digest,
        repository="yanhul/AIOS", sha="a" * 40, attempt=1, now=now,
    )
    receipt["status"] = "UNKNOWN"
    receipt["execution_state"] = "IN_PROGRESS_OR_AMBIGUOUS"
    receipt["failure_code"] = None
    sign_receipt(receipt, SIGNED_FIELDS)
    signer = GatewayRetryPermitSigner(Ed25519PrivateKey.generate())
    with pytest.raises(GatewayTransportError, match="does not prove Gemini was never submitted"):
        prepare_gateway_retry_permit(
            _FakeGatewayRetryTransport(ticket_state=ticket_state), ticket="T-RETRY",
            aios_dir=str(tmp_path), effect_id=effect["effect_id"], actor="aios",
            operation_receipt=receipt, issuer="operator:test", reason="not enough evidence",
            issuer_secret=ISSUER_SECRETS["operator:test"], retry_keyring=RETRY_KEYRING,
            signer=signer, operation_keyring=operation_keyring, now=now,
        )


def test_unmapped_later_gateway_attempt_blocks_issuing_another_permit(tmp_path):
    import time
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _contract, _permit, effect, dispatched, request_digest, _receipt_digest, ticket_state = _gateway_retry_fixture(tmp_path)
    now = time.time()
    operation_keyring = _try_receipt_keyring()
    receipt = _signed_try_preflight_receipt(
        request_id=dispatched["attempt_id"], request_digest=request_digest,
        repository="yanhul/AIOS", sha="a" * 40, attempt=1, now=now,
    )
    # Simulate Gateway committed fence 2 but AIOS crashed before persisting the mapping.
    ticket_state["attempts"] = 2
    ticket_state["attempt_history"].append({
        "attempt_id": "T-RETRY:2", "attempt_number": 2, "fence": 2, "status": "DISPATCHED",
    })
    signer = GatewayRetryPermitSigner(Ed25519PrivateKey.generate())
    with pytest.raises(GatewayTransportError, match="later/unmapped attempt"):
        prepare_gateway_retry_permit(
            _FakeGatewayRetryTransport(ticket_state=ticket_state), ticket="T-RETRY",
            aios_dir=str(tmp_path), effect_id=effect["effect_id"], actor="aios",
            operation_receipt=receipt, issuer="operator:test", reason="must remain blocked",
            issuer_secret=ISSUER_SECRETS["operator:test"], retry_keyring=RETRY_KEYRING,
            signer=signer, operation_keyring=operation_keyring, now=now,
        )
    assert not list((tmp_path / "gateway_retry_permits").glob("*.json"))


def test_gateway_retry_replay_crash_gap_never_maps_or_executes(tmp_path):
    import time
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    contract, permit, effect, dispatched, request_digest, _receipt_digest, ticket_state = _gateway_retry_fixture(tmp_path)
    now = time.time()
    operation_keyring = _try_receipt_keyring()
    receipt = _signed_try_preflight_receipt(
        request_id=dispatched["attempt_id"], request_digest=request_digest,
        repository="yanhul/AIOS", sha="a" * 40, attempt=1, now=now,
    )
    signer = GatewayRetryPermitSigner(Ed25519PrivateKey.generate())
    permit_record = prepare_gateway_retry_permit(
        _FakeGatewayRetryTransport(ticket_state=ticket_state), ticket="T-RETRY",
        aios_dir=str(tmp_path), effect_id=effect["effect_id"], actor="aios",
        operation_receipt=receipt, issuer="operator:test", reason="verified not submitted",
        issuer_secret=ISSUER_SECRETS["operator:test"], retry_keyring=RETRY_KEYRING,
        signer=signer, operation_keyring=operation_keyring, now=now,
    )
    replay = {"effect_id": effect["effect_id"], "ticket_id": "T-RETRY", "attempt_id": "T-RETRY:2",
             "attempt_number": 2, "fence": 2, "target_sha": "a" * 40,
             "evidence_ref": "EV-1", "lineage_ref": "LIN-1", "idempotency_key": "idem-1",
             "retry_permit_id": permit_record["permit_id"], "replayed": True, "execute_allowed": False}
    transport = _FakeGatewayRetryTransport(ticket_state=ticket_state, retry_response=replay)
    with pytest.raises(GatewayTransportError, match="replayed/non-executable"):
        retry_gateway_effect(
            transport, ticket="T-RETRY", aios_dir=str(tmp_path), effect_id=effect["effect_id"],
            actor="aios", provider="try.repair", retry_permit=permit_record,
            signer=signer, retry_keyring=RETRY_KEYRING, now=now,
        )
    current = json.loads((tmp_path / "effects" / f"{effect['effect_id']}.json").read_text())
    assert current["state"] == "UNKNOWN"
    assert current["attempt"] == 1
    assert current["gateway_attempt_id"] == "T-RETRY:1"
    assert transport.retry_calls == 1


def _real_gateway_retry_setup(tmp_path, monkeypatch):
    import json, os, time
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from core.gateway_effect_adapter import GatewayCLITransport
    cli = os.environ.get("HARNESS_GATEWAY_CLI")
    if not cli:
        pytest.skip("HARNESS_GATEWAY_CLI is only configured in cross-repository CI")
    contract, permit, attestation, effect = _authority(tmp_path)
    target_sha = "a" * 40
    governance = {key: "sha256:" + key for key in (
        "policy", "evidence_criteria", "promotion_criteria", "terminal_conditions", "trust_roots")}
    client = GatewayCLITransport(cli_path=cli, state_path=tmp_path / "gateway-v5.json",
                                 human_identity="human:test", governance=governance)
    gateway_contract = {
        "protocol_version": 5, "effect_id": effect["effect_id"],
        "contract_id": contract_identity(contract), "actor": "aios",
        "action": "run_research", "capability_ref": "try.repair@1",
        "authority_ref": permit["permit_id"], "evidence_ref": "EV-1",
        "lineage_ref": "LIN-1", "idempotency_key": "idem-1",
    }
    client.create_ticket(ticket="T-RETRY", repository="yanhul/AIOS", target_sha=target_sha,
                         nonce="nonce-1", ttl_seconds=600, effect_contract=gateway_contract)
    client.authorize(ticket="T-RETRY", nonce="nonce-1", sender="human:test", target_sha=target_sha)
    initial = begin_and_dispatch_aios_effect(
        client, ticket="T-RETRY", target_sha=target_sha, aios_dir=str(tmp_path),
        effect=effect, actor="aios", provider="try.repair", evidence_ref="EV-1",
        lineage_ref="LIN-1", idempotency_key="idem-1",
    )
    current = initial["effect"]
    request_body = {"request_id": current["attempt_id"], "repository": "yanhul/AIOS",
                    "sha": target_sha, "attempt": 1, "failure": {}, "source_snapshot": {"core/a.py": "x"}}
    from core.try_repair_provider import _request_digest
    request_digest = _request_digest(request_body)
    bind_try_operation_request(str(tmp_path), effect["effect_id"], "aios",
                               request_id=current["attempt_id"], request_digest=request_digest,
                               repository="yanhul/AIOS", sha=target_sha)
    receipt = {"ticket_id": "T-RETRY", "attempt_id": current["gateway_attempt_id"],
               "attempt_fence": current["attempt_fence"], "target_sha": target_sha,
               "effect_id": effect["effect_id"], "status": "UNKNOWN",
               "evidence_ref": "EV-1", "lineage_ref": "LIN-1"}
    record_gateway_receipt(client, ticket="T-RETRY", aios_dir=str(tmp_path),
                           effect_id=effect["effect_id"], actor="aios", receipt=receipt)
    now = time.time()
    operation_keyring = _try_receipt_keyring()
    operation_receipt = _signed_try_preflight_receipt(
        request_id=current["attempt_id"], request_digest=request_digest,
        repository="yanhul/AIOS", sha=target_sha, attempt=1, now=now)
    private = Ed25519PrivateKey.generate()
    signer = GatewayRetryPermitSigner(private)
    public_keys = {signer.key_id: signer.public_key_hex}
    monkeypatch.setenv("AIOS_GATEWAY_RETRY_PUBLIC_KEYS", json.dumps(public_keys))
    permit_record = prepare_gateway_retry_permit(
        client, ticket="T-RETRY", aios_dir=str(tmp_path), effect_id=effect["effect_id"], actor="aios",
        operation_receipt=operation_receipt, issuer="operator:test", reason="verified TRY preflight non-submission",
        issuer_secret=ISSUER_SECRETS["operator:test"], retry_keyring=RETRY_KEYRING,
        signer=signer, operation_keyring=operation_keyring, now=now)
    return client, effect, signer, permit_record, operation_keyring, operation_receipt, now


def test_real_gateway_v5_retry_permit_end_to_end(tmp_path, monkeypatch):
    client, effect, signer, permit_record, _operation_keyring, _operation_receipt, now = _real_gateway_retry_setup(tmp_path, monkeypatch)
    result = retry_gateway_effect(
        client, ticket="T-RETRY", aios_dir=str(tmp_path), effect_id=effect["effect_id"], actor="aios",
        provider="try.repair", retry_permit=permit_record, signer=signer,
        retry_keyring=RETRY_KEYRING, now=now)
    assert result["execute_allowed"] is True
    assert result["effect"]["state"] == "DISPATCHED"
    assert result["effect"]["attempt"] == 2
    assert result["effect"]["gateway_attempt_id"] == "T-RETRY:2"
    assert result["attempt_fence"] == 2
    saved = client.status()["tickets"]["T-RETRY"]
    assert [a["fence"] for a in saved["attempt_history"]] == [1, 2]
    assert saved["retry_permit_history"][0]["permit_id"] == permit_record["permit_id"]


def test_real_gateway_v5_crash_after_allocation_replay_is_never_executable(tmp_path, monkeypatch):
    client, effect, signer, permit_record, operation_keyring, operation_receipt, now = _real_gateway_retry_setup(tmp_path, monkeypatch)
    allocated = client.retry_effect(ticket="T-RETRY", retry_permit=permit_record)
    assert allocated["execute_allowed"] is True
    # Simulate process death after Gateway commit but before AIOS maps/executes.
    with pytest.raises(GatewayTransportError, match="replayed/non-executable"):
        retry_gateway_effect(
            client, ticket="T-RETRY", aios_dir=str(tmp_path), effect_id=effect["effect_id"], actor="aios",
            provider="try.repair", retry_permit=permit_record, signer=signer,
            retry_keyring=RETRY_KEYRING, now=now)
    current = json.loads((tmp_path / "effects" / f"{effect['effect_id']}.json").read_text())
    assert current["state"] == "UNKNOWN"
    assert current["attempt"] == 1
    assert current["gateway_attempt_id"] == "T-RETRY:1"
    saved = client.status()["tickets"]["T-RETRY"]
    assert saved["attempts"] == 2
    assert saved["attempt_history"][1]["fence"] == 2
    assert saved["attempt_history"][1]["status"] == "DISPATCHED"
    with pytest.raises(GatewayTransportError, match="later/unmapped attempt"):
        prepare_gateway_retry_permit(
            client, ticket="T-RETRY", aios_dir=str(tmp_path), effect_id=effect["effect_id"], actor="aios",
            operation_receipt=operation_receipt, issuer="operator:test", reason="must stay blocked",
            issuer_secret=ISSUER_SECRETS["operator:test"], retry_keyring=RETRY_KEYRING,
            signer=signer, operation_keyring=operation_keyring, now=now,
        )
