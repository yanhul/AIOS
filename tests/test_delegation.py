# AIOS-CONTRACT: delegation requires an existing execution contract/permit and never mints authority
# AIOS-REGRESSION: delegated handoffs must remain bound to target capability and execution lineage
# AIOS-OWNER: AIOS control plane / delegation boundary
# AIOS-COVERAGE-GAP: no multi-worker runtime is covered; this test covers the durable proposal boundary
# AIOS-BASELINE: main at PR creation; exercised against the existing contract, capability, and lineage primitives

import tempfile
import unittest

from core.capabilities import Capability, CapabilityRegistry
from core.contract import issue_permit, contract_identity
from core.delegation import DelegationError, build_delegation, load_delegation, persist_delegation, validate_delegation
from core.execution_lineage import ExecutionLineage


def _context():
    contract = {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "task-1",
        "scope": "project-1",
        "actor": "AIOS",
        "capabilities": ["worker.target@1"],
        "input_digest": "input-1",
        "allowed_effects": ["delegate", "memory_write"],
        "evidence_required": ["receipt"],
        "max_attempts": 2,
        "terminal_states": ["PASS", "BLOCKED"],
        "policy_digest": "policy-1",
    }
    permit = issue_permit(contract, "AIOS_CONTROL_PLANE")
    registry = CapabilityRegistry()
    registry.register(Capability(
        capability_id="worker.target",
        version="1",
        owner="test",
        kind="worker",
        status="ACTIVE",
        inputs=("input",),
        outputs=("receipt",),
    ))
    lineage = ExecutionLineage(
        policy_revision="policy-1",
        environment_revision="env-1",
        capability_snapshot={"worker.target@1": "ACTIVE"},
        provider_revision="provider-1",
        attempt_id="attempt-1",
        trajectory_id="trajectory-1",
    )
    return contract, permit, registry, lineage


class GovernedDelegationTests(unittest.TestCase):
    def test_build_is_bound_to_existing_authority(self):
        contract, permit, registry, lineage = _context()
        request = build_delegation(
            contract=contract, permit=permit, source_actor="AIOS",
            target_role="verifier", authority_mode="caller_bound", credential_ref="cred:caller",
            memory_scope="private", target_capability="worker.target@1", operation_id="verify-1", input_digest="input-1",
            evidence_required=["receipt"], lineage=lineage, registry=registry,
        )
        self.assertTrue(request.delegation_id.startswith("DG-"))
        validate_delegation(request, contract=contract, permit=permit, registry=registry)

    def test_delegation_never_grants_authority(self):
        contract, permit, registry, lineage = _context()
        request = build_delegation(
            contract=contract, permit=permit, source_actor="AIOS",
            target_role="verifier", authority_mode="caller_bound", credential_ref="cred:caller",
            memory_scope="private", target_capability="worker.target@1", operation_id="verify-1", input_digest="input-1",
            evidence_required=["receipt"], lineage=lineage, registry=registry,
        )
        self.assertEqual(request.source_permit_id, permit["permit_id"])
        self.assertEqual(request.source_contract_id, contract_identity(contract))
        self.assertNotIn("issuer", request.as_dict())
        self.assertEqual(request.state, "PROPOSED")

    def test_unknown_target_capability_blocks(self):
        contract, permit, registry, lineage = _context()
        with self.assertRaises(DelegationError):
            build_delegation(
                contract=contract, permit=permit, source_actor="AIOS",
                target_role="verifier", authority_mode="none", credential_ref=None,
                memory_scope="private", target_capability="missing@1",
                operation_id="verify-1", input_digest="input-1",
                evidence_required=["receipt"], lineage=lineage, registry=registry,
            )

    def test_authority_is_not_implicitly_inherited(self):
        contract, permit, registry, lineage = _context()
        with self.assertRaises(DelegationError):
            build_delegation(
                contract=contract, permit=permit, source_actor="AIOS",
                target_role="worker", authority_mode="caller_bound", credential_ref=None,
                memory_scope="private", target_capability="worker.target@1",
                operation_id="run-1", input_digest="input-1",
                evidence_required=["receipt"], lineage=lineage, registry=registry,
            )

    def test_shared_memory_requires_explicit_permit(self):
        contract, permit, registry, lineage = _context()
        permit = dict(permit)
        contract = dict(contract)
        contract["allowed_effects"] = ["delegate"]
        permit = issue_permit(contract, "AIOS_CONTROL_PLANE")
        with self.assertRaises(DelegationError):
            build_delegation(
                contract=contract, permit=permit, source_actor="AIOS",
                target_role="worker", authority_mode="none", credential_ref=None,
                memory_scope="shared", target_capability="worker.target@1",
                operation_id="run-1", input_digest="input-1",
                evidence_required=["receipt"], lineage=lineage, registry=registry,
            )

    def test_service_bound_requires_service_credential_ref(self):
        contract, permit, registry, lineage = _context()
        with self.assertRaises(DelegationError):
            build_delegation(
                contract=contract, permit=permit, source_actor="AIOS",
                target_role="worker", authority_mode="service_bound", credential_ref=None,
                memory_scope="private", target_capability="worker.target@1",
                operation_id="run-1", input_digest="input-1",
                evidence_required=["receipt"], lineage=lineage, registry=registry,
            )

    def test_service_bound_cannot_carry_caller_credential(self):
        contract, permit, registry, lineage = _context()
        with self.assertRaises(DelegationError):
            build_delegation(
                contract=contract, permit=permit, source_actor="AIOS",
                target_role="worker", authority_mode="service_bound", credential_ref="cred:caller",
                memory_scope="private", target_capability="worker.target@1",
                operation_id="run-1", input_digest="input-1",
                evidence_required=["receipt"], lineage=lineage, registry=registry,
            )

    def test_tampered_lineage_blocks_load(self):
        contract, permit, registry, lineage = _context()
        request = build_delegation(
            contract=contract, permit=permit, source_actor="AIOS",
            target_role="verifier", authority_mode="caller_bound", credential_ref="cred:caller",
            memory_scope="private", target_capability="worker.target@1", operation_id="verify-1", input_digest="input-1",
            evidence_required=["receipt"], lineage=lineage, registry=registry,
        )
        record = request.as_dict()
        record["lineage"]["attempt_id"] = "tampered"
        with self.assertRaises(ValueError):
            load_delegation(record)

    def test_persist_and_reload(self):
        contract, permit, registry, lineage = _context()
        request = build_delegation(
            contract=contract, permit=permit, source_actor="AIOS",
            target_role="verifier", authority_mode="caller_bound", credential_ref="cred:caller",
            memory_scope="private", target_capability="worker.target@1", operation_id="verify-1", input_digest="input-1",
            evidence_required=["receipt"], lineage=lineage, registry=registry,
        )
        with tempfile.TemporaryDirectory() as tmp:
            persist_delegation(tmp, request)
            import json
            with open(f"{tmp}/delegations/{request.delegation_id}.json", encoding="utf-8") as fh:
                restored = load_delegation(json.load(fh))
        self.assertEqual(restored, request)


if __name__ == "__main__":
    unittest.main()
