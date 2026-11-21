"""Firestore Emulator integration for M10/M11 atomic activation and CAS."""
import hashlib
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from google.auth.credentials import AnonymousCredentials
from google.cloud import firestore
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.firestore_authority import FirestoreAuthorityStore, record_digest
from core.firestore_evolution_store import EvolutionStoreError, FirestoreEvolutionStore
from core.firestore_effect_store import FirestoreEffectStore
from core.mutation import canonical_json

PROJECT = os.environ.get("AIOS_FIRESTORE_PROJECT_ID", "aios-emulator-test")
pytestmark = pytest.mark.skipif(not os.environ.get("FIRESTORE_EMULATOR_HOST"), reason="requires Firestore Emulator")


def signed_store(client):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    key_id = "ed25519:" + hashlib.sha256(bytes.fromhex(public)).hexdigest()[:32]
    anchor = {key_id: {"public_key": public, "principal": "emulator-authority", "revoked": False}}
    authority = FirestoreAuthorityStore(client, project_id=PROJECT)

    def put(kind, record):
        issued = int(time.time()) - 5
        envelope = {"type": "AIOS_AUTHORITY_SIGNATURE", "algorithm": "Ed25519",
                    "key_id": key_id, "principal": "emulator-authority",
                    "record_digest": record_digest(record), "issued_at": issued,
                    "expires_at": issued + 3600}
        envelope["signature"] = private.sign(canonical_json(envelope).encode()).hex()
        return authority.put_immutable(record_type=kind, record_id=uuid.uuid4().hex,
                                       record=record, signature=envelope, trust_anchor=anchor)
    return authority, anchor, put


def make_store():
    client = firestore.Client(project=PROJECT, credentials=AnonymousCredentials())
    authority, anchor, put = signed_store(client)
    activation_client = firestore.Client(project=PROJECT + "-activation", credentials=AnonymousCredentials())
    store = FirestoreEvolutionStore(client, project_id=PROJECT, authority_store=authority,
                                    activation_client=activation_client, trust_anchor=anchor,
                                    expected_workflow_sha256="9" * 64)
    return store, authority, put


def add_ci(store, source_sha, suffix):
    result = store.record_ci_evidence({
        "repository": "yanhul/AIOS", "workflow_id": 7,
        "workflow_path": ".github/workflows/firestore-emulator.yml",
        "workflow_sha256": "9" * 64,
        "workflow_name": "Firestore Emulator Gate", "run_id": int(suffix),
        "run_attempt": 1, "run_url": "https://github.com/yanhul/AIOS/actions/runs/" + suffix,
        "head_branch": "integration-test", "head_sha": source_sha,
        "event": "workflow_dispatch", "conclusion": "success",
        "jobs": [{"id": int(suffix), "name": "firestore-emulator", "conclusion": "success"}],
        "artifact_digests": [{"name": f"firestore-emulator-{suffix}", "id": int(suffix),
                              "size_in_bytes": 1, "sha256": hashlib.sha256(suffix.encode()).hexdigest()}],
    }, actor="emulator-ci-ingestor")
    return result["evidence_ref"]


def test_emulator_bootstrap_promotion_replay_and_concurrent_cas():
    store, authority, put = make_store()
    capability_id = "emulator.capability." + uuid.uuid4().hex
    source_sha = hashlib.sha1(uuid.uuid4().bytes).hexdigest()
    base_cap = {"capability_id": capability_id, "version": "1.0.0", "status": "ACTIVE",
                "source_commit": source_sha, "patch_digest": "1" * 64}
    base_digest = put("CAPABILITY", base_cap)
    bootstrap_digest = put("CAPABILITY_BOOTSTRAP_DECISION", {
        "decision": "BOOTSTRAP_ACTIVE", "capability_id": capability_id,
        "version": "1.0.0", "capability_digest": base_digest,
        "revision": 0, "previous_decision_digest": None,
    })
    assert store.bootstrap_active_capability(capability_digest=base_digest,
                                             bootstrap_decision_digest=bootstrap_digest)["status"] == "ACTIVE"

    ci_ref = add_ci(store, source_sha, str(100000 + int(uuid.uuid4().hex[:6], 16)))
    candidate = store.propose_candidate({
        "record_type": "CAPABILITY_CANDIDATE", "capability_id": capability_id,
        "base_version": "1.0.0", "candidate_version": "1.1.0",
        "proposer": "agent-proposer", "source_commit": source_sha,
        "patch_digest": "2" * 64, "change_summary": "emulator candidate",
        "evidence_refs": [ci_ref], "run_id": "candidate-" + uuid.uuid4().hex,
    }, actor="emulator-ledger")
    candidate_id = candidate["record_id"]
    evaluation = store.evaluate_candidate({
        "candidate_id": candidate_id, "evaluator": "independent-evaluator",
        "evaluator_version": "emulator-verifier@1", "verdict": "PASS",
        "test_suite_digest": "3" * 64, "comparison_digest": "4" * 64,
        "evidence_refs": [ci_ref], "run_id": "evaluation-" + uuid.uuid4().hex,
    }, actor="emulator-ledger")
    evaluation_id = evaluation["evaluation_id"]

    # M10 PASS ingestion must bind to the exact Firestore effect/attempt/receipt
    # and the same independent M11 PASS evaluator; it cannot trust caller text.
    effect_store = FirestoreEffectStore(store.client, project_id=PROJECT)
    effect_id = "effect-" + uuid.uuid4().hex
    attempt_id = effect_id + ":attempt:1"
    receipt_id = "receipt-" + uuid.uuid4().hex
    lineage_digest = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    effect_store.create_effect({
        "effect_id": effect_id, "contract_id": "contract-fixture", "permit_id": "permit-fixture",
        "actor": "emulator-worker", "effect_type": "external_effect", "policy_digest": "policy-fixture",
        "max_attempts": 1, "state": "PLANNED",
    })
    effect_store.dispatch(effect_id=effect_id, attempt_id=attempt_id, provider="fixture-provider",
                          expected_revision=0, lineage={"lineage": {"lineage_digest": lineage_digest}})
    effect_store.record_verified_receipt(
        effect_id=effect_id, attempt_id=attempt_id,
        receipt={"receipt_id": receipt_id, "provider": "fixture-provider",
                 "provider_operation_id": "operation-" + uuid.uuid4().hex,
                 "outcome": "OBSERVED_SUCCESS", "observation": {"status": "done"},
                 "observation_digest": "sha256:emulator-observation"},
        verified_authentication={"algorithm": "Ed25519", "verified": True}, expected_revision=1,
    )
    experience = store.record_experience({
        "record_type": "EXPERIENCE", "capability_id": capability_id,
        "capability_version": "1.1.0", "task_id": "task-" + uuid.uuid4().hex,
        "outcome": "PASS", "contributor": "agent-proposer",
        "evidence_refs": [ci_ref, f"effect://{effect_id}", f"attempt://{effect_id}/{attempt_id}",
                          f"receipt://{receipt_id}", f"evaluation://{evaluation_id}"],
        "run_id": "experience-" + uuid.uuid4().hex, "source_commit": source_sha,
        "artifact_digest": "2" * 64, "effect_id": effect_id, "attempt_id": attempt_id,
        "receipt_id": receipt_id, "verifier": "independent-evaluator",
        "evaluation_id": evaluation_id, "verification_status": "VERIFIED_DIGITAL",
    }, actor="emulator-experience-ledger")
    assert experience["record_id"].startswith("XP-")

    new_cap = {"capability_id": capability_id, "version": "1.1.0", "status": "ACTIVE",
               "source_commit": source_sha, "patch_digest": "2" * 64,
               "candidate_id": candidate_id, "evaluation_id": evaluation_id}
    new_cap_digest = put("CAPABILITY", new_cap)
    decision_digest = put("CAPABILITY_PROMOTION_DECISION", {
        "decision": "PROMOTED", "candidate_id": candidate_id,
        "evaluation_id": evaluation_id, "capability_id": capability_id,
        "from_version": "1.0.0", "to_version": "1.1.0",
        "approver": "independent-approver", "evidence_refs": [ci_ref],
        "capability_digest": new_cap_digest, "revision": 1,
        "previous_decision_digest": bootstrap_digest,
    })

    def promote(_):
        return store.promote_candidate(candidate_id=candidate_id, evaluation_id=evaluation_id,
                                       decision_digest=decision_digest, capability_digest=new_cap_digest,
                                       repository="yanhul/AIOS")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(promote, range(2)))
    assert all(result["status"] == "ACTIVE" for result in results)
    assert sorted(result["replayed"] for result in results) == [False, True]
    active = store.get_active_capability(capability_id)
    assert active["pointer"]["version"] == "1.1.0"
    assert active["capability"] == new_cap


def test_emulator_promotion_rejects_stale_base_after_another_activation():
    store, authority, put = make_store()
    capability_id = "emulator.stale." + uuid.uuid4().hex
    source_sha = hashlib.sha1(uuid.uuid4().bytes).hexdigest()
    base = {"capability_id": capability_id, "version": "1.0.0", "status": "ACTIVE",
            "source_commit": source_sha, "patch_digest": "a" * 64}
    base_digest = put("CAPABILITY", base)
    bootstrap = put("CAPABILITY_BOOTSTRAP_DECISION", {"decision": "BOOTSTRAP_ACTIVE",
        "capability_id": capability_id, "version": "1.0.0", "capability_digest": base_digest,
        "revision": 0, "previous_decision_digest": None})
    store.bootstrap_active_capability(capability_digest=base_digest, bootstrap_decision_digest=bootstrap)
    ci_ref = add_ci(store, source_sha, str(200000 + int(uuid.uuid4().hex[:6], 16)))
    candidate = store.propose_candidate({"record_type": "CAPABILITY_CANDIDATE", "capability_id": capability_id,
        "base_version": "1.0.0", "candidate_version": "1.1.0", "proposer": "p1",
        "source_commit": source_sha, "patch_digest": "b" * 64, "change_summary": "first",
        "evidence_refs": [ci_ref], "run_id": "r1"}, actor="ledger")
    evaluation = store.evaluate_candidate({"candidate_id": candidate["record_id"], "evaluator": "e1",
        "evaluator_version": "v1", "verdict": "PASS", "test_suite_digest": "c" * 64,
        "comparison_digest": "d" * 64, "evidence_refs": [ci_ref], "run_id": "e1"}, actor="ledger")
    new_cap = {"capability_id": capability_id, "version": "1.1.0", "status": "ACTIVE",
        "source_commit": source_sha, "patch_digest": "b" * 64,
        "candidate_id": candidate["record_id"], "evaluation_id": evaluation["evaluation_id"]}
    new_cap_digest = put("CAPABILITY", new_cap)
    decision = put("CAPABILITY_PROMOTION_DECISION", {"decision": "PROMOTED",
        "candidate_id": candidate["record_id"], "evaluation_id": evaluation["evaluation_id"],
        "capability_id": capability_id, "from_version": "1.0.0", "to_version": "1.1.0",
        "approver": "a1", "evidence_refs": [ci_ref], "capability_digest": new_cap_digest,
        "revision": 1, "previous_decision_digest": bootstrap})
    store.promote_candidate(candidate_id=candidate["record_id"], evaluation_id=evaluation["evaluation_id"],
        decision_digest=decision, capability_digest=new_cap_digest, repository="yanhul/AIOS")

    # A second candidate still based on 1.0.0 cannot overwrite the active 1.1.0.
    stale = store.propose_candidate({"record_type": "CAPABILITY_CANDIDATE", "capability_id": capability_id,
        "base_version": "1.0.0", "candidate_version": "1.2.0", "proposer": "p2",
        "source_commit": source_sha, "patch_digest": "e" * 64, "change_summary": "stale",
        "evidence_refs": [ci_ref], "run_id": "r2"}, actor="ledger")
    stale_eval = store.evaluate_candidate({"candidate_id": stale["record_id"], "evaluator": "e2",
        "evaluator_version": "v1", "verdict": "PASS", "test_suite_digest": "f" * 64,
        "comparison_digest": "0" * 64, "evidence_refs": [ci_ref], "run_id": "e2"}, actor="ledger")
    stale_cap = {"capability_id": capability_id, "version": "1.2.0", "status": "ACTIVE",
        "source_commit": source_sha, "patch_digest": "e" * 64,
        "candidate_id": stale["record_id"], "evaluation_id": stale_eval["evaluation_id"]}
    stale_cap_digest = put("CAPABILITY", stale_cap)
    stale_decision = put("CAPABILITY_PROMOTION_DECISION", {"decision": "PROMOTED",
        "candidate_id": stale["record_id"], "evaluation_id": stale_eval["evaluation_id"],
        "capability_id": capability_id, "from_version": "1.0.0", "to_version": "1.2.0",
        "approver": "a2", "evidence_refs": [ci_ref], "capability_digest": stale_cap_digest,
        "revision": 2, "previous_decision_digest": decision})
    with pytest.raises(EvolutionStoreError, match="active capability base version mismatch"):
        store.promote_candidate(candidate_id=stale["record_id"], evaluation_id=stale_eval["evaluation_id"],
            decision_digest=stale_decision, capability_digest=stale_cap_digest, repository="yanhul/AIOS")


def test_activation_reconciles_crash_before_pointer_and_after_pointer_before_finalize():
    client = firestore.Client(project=PROJECT, credentials=AnonymousCredentials())
    activation_client = firestore.Client(project=PROJECT + "-activation", credentials=AnonymousCredentials())
    authority, anchor, put = signed_store(client)
    capability_id = "activation-crash." + uuid.uuid4().hex
    capability = {"capability_id": capability_id, "version": "1.0.0", "status": "ACTIVE",
                  "source_commit": hashlib.sha1(uuid.uuid4().bytes).hexdigest(), "patch_digest": "a" * 64}
    capability_digest = put("CAPABILITY", capability)
    decision_digest = put("CAPABILITY_BOOTSTRAP_DECISION", {
        "decision": "BOOTSTRAP_ACTIVE", "capability_id": capability_id,
        "version": "1.0.0", "capability_digest": capability_digest,
        "revision": 0, "previous_decision_digest": None,
    })
    store = FirestoreEvolutionStore(client, project_id=PROJECT, authority_store=authority,
                                    activation_client=activation_client, trust_anchor=anchor,
                                    expected_workflow_sha256="9" * 64)
    original_run = store._run
    failed = {"activation": False}

    def crash_before_pointer(tx_client, callback):
        if tx_client is activation_client and not failed["activation"]:
            failed["activation"] = True
            raise RuntimeError("simulated process crash before pointer write")
        return original_run(tx_client, callback)

    store._run = crash_before_pointer
    with pytest.raises(EvolutionStoreError, match="was not confirmed"):
        store.bootstrap_active_capability(capability_digest=capability_digest,
                                          bootstrap_decision_digest=decision_digest)
    operation_id = "BOOTSTRAP-" + decision_digest
    assert store._ref("aios_activation_operations", operation_id).get().to_dict()["state"] == "PREPARED"
    assert store._ref("aios_active_capabilities", capability_id).get().exists is False

    # Re-run after crash: PREPARED is durable and the same signed operation is idempotently completed.
    store._run = original_run
    result = store.bootstrap_active_capability(capability_digest=capability_digest,
                                               bootstrap_decision_digest=decision_digest)
    assert result["status"] == "ACTIVE"
    assert result["activation_state"] == "ACTIVATED"
    assert store._ref("aios_activation_operations", operation_id).get().to_dict()["state"] == "ACTIVATED"
    assert store.get_active_capability(capability_id)["pointer"]["bootstrap_decision_digest"] == decision_digest

    # Simulate a crash after pointer durability but before the ledger finalize phase.
    capability_id_2 = capability_id + ".second"
    capability_2 = {**capability, "capability_id": capability_id_2}
    digest_2 = put("CAPABILITY", capability_2)
    decision_2 = put("CAPABILITY_BOOTSTRAP_DECISION", {
        "decision": "BOOTSTRAP_ACTIVE", "capability_id": capability_id_2,
        "version": "1.0.0", "capability_digest": digest_2,
        "revision": 0, "previous_decision_digest": None,
    })
    calls = {"evolution": 0}
    def crash_before_finalize(tx_client, callback):
        if tx_client is client:
            calls["evolution"] += 1
            if calls["evolution"] == 2:
                raise RuntimeError("simulated process crash before finalize")
        return original_run(tx_client, callback)
    store._run = crash_before_finalize
    with pytest.raises(EvolutionStoreError, match="was not confirmed"):
        store.bootstrap_active_capability(capability_digest=digest_2,
                                          bootstrap_decision_digest=decision_2)
    operation_id_2 = "BOOTSTRAP-" + decision_2
    assert store._ref("aios_activation_operations", operation_id_2).get().to_dict()["state"] == "PREPARED"
    assert store._ref("aios_active_capabilities", capability_id_2).get().exists is True
    store._run = original_run
    result_2 = store.bootstrap_active_capability(capability_digest=digest_2,
                                                 bootstrap_decision_digest=decision_2)
    assert result_2["activation_state"] == "ACTIVATED"
    assert store._ref("aios_activation_operations", operation_id_2).get().to_dict()["state"] == "ACTIVATED"
