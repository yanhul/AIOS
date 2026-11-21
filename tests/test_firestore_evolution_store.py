from copy import deepcopy

import pytest

from core.firestore_evolution_store import EvolutionStoreError, FirestoreEvolutionStore


class Snapshot:
    def __init__(self, value):
        self.exists = value is not None
        self.value = deepcopy(value)

    def to_dict(self):
        return deepcopy(self.value)


class Ref:
    def __init__(self, client, path):
        self.client, self.path = client, path

    def collection(self, name):
        return Collection(self.client, self.path + "/" + name)

    def get(self, transaction=None):
        source = transaction.data if transaction is not None else self.client.data
        return Snapshot(source.get(self.path))


class Collection:
    def __init__(self, client, path):
        self.client, self.path = client, path

    def document(self, key):
        return Ref(self.client, self.path + "/" + key)


class Transaction:
    def __init__(self, client):
        self.data = deepcopy(client.data)

    def create(self, ref, value):
        if ref.path in self.data:
            raise RuntimeError("already exists")
        self.data[ref.path] = deepcopy(value)

    def set(self, ref, value):
        self.data[ref.path] = deepcopy(value)


class Client:
    project = "evolution-test"

    def __init__(self):
        self.data = {}

    def collection(self, name):
        return Collection(self, name)


class Authority:
    def __init__(self, records):
        self.records = records

    def get_verified(self, digest, *, trust_anchor, expected_type=None):
        record_type, record = self.records[digest]
        if record_type != expected_type:
            raise ValueError("wrong authority artifact type")
        return deepcopy(record)


def runner(client, callback):
    tx = Transaction(client)
    result = callback(tx)
    client.data = tx.data
    return result


def fixture():
    client = Client()
    capability = {
        "capability_id": "research.deep", "version": "1.0.0", "status": "ACTIVE",
        "source_commit": "a" * 40, "patch_digest": "b" * 64,
    }
    authority = Authority({
        "boot-digest": ("CAPABILITY_BOOTSTRAP_DECISION", {
            "decision": "BOOTSTRAP_ACTIVE", "capability_id": "research.deep",
            "version": "1.0.0", "capability_digest": "base-cap-digest",
            "revision": 0, "previous_decision_digest": None,
        }),
        "base-cap-digest": ("CAPABILITY", capability),
    })
    store = FirestoreEvolutionStore(
        client, project_id=client.project, authority_store=authority,
        trust_anchor={"test": {}}, transaction_runner=runner,
        expected_workflow_sha256="9" * 64,
    )
    store.bootstrap_active_capability(
        capability_digest="base-cap-digest", bootstrap_decision_digest="boot-digest",
    )
    return store, client, authority


def ci_record(source_commit="c" * 40):
    return {
        "repository": "yanhul/AIOS", "workflow_id": 42,
        "workflow_path": ".github/workflows/firestore-emulator.yml",
        "workflow_sha256": "9" * 64,
        "workflow_name": "Firestore Emulator Gate", "run_id": 1234,
        "run_attempt": 1, "run_url": "https://github.com/yanhul/AIOS/actions/runs/1234",
        "head_branch": "candidate", "head_sha": source_commit,
        "event": "pull_request", "conclusion": "success",
        "jobs": [{"id": 1, "name": "firestore-emulator", "conclusion": "success"}],
        "artifact_digests": [{"name": "firestore-emulator-1234", "id": 55,
                              "size_in_bytes": 1024, "sha256": "d" * 64}],
    }


def prepare_promotion(store, authority, *, source_commit="c" * 40):
    ci = store.record_ci_evidence(ci_record(source_commit), actor="ci-ingestor")
    ci_ref = ci["evidence_ref"]
    candidate = store.propose_candidate({
        "record_type": "CAPABILITY_CANDIDATE", "capability_id": "research.deep",
        "base_version": "1.0.0", "candidate_version": "1.1.0",
        "proposer": "agent-proposer", "source_commit": source_commit,
        "patch_digest": "e" * 64, "change_summary": "Improve retrieval",
        "evidence_refs": [ci_ref], "run_id": "candidate-run-1",
    }, actor="ledger")
    candidate_id = candidate["record_id"]
    evaluation = store.evaluate_candidate({
        "candidate_id": candidate_id, "evaluator": "independent-evaluator",
        "evaluator_version": "verifier@1", "verdict": "PASS",
        "test_suite_digest": "f" * 64, "comparison_digest": "1" * 64,
        "evidence_refs": [ci_ref], "run_id": "evaluation-run-1",
    }, actor="ledger")
    evaluation_id = evaluation["evaluation_id"]
    new_capability = {
        "capability_id": "research.deep", "version": "1.1.0", "status": "ACTIVE",
        "source_commit": source_commit, "patch_digest": "e" * 64,
        "candidate_id": candidate_id, "evaluation_id": evaluation_id,
    }
    decision = {
        "decision": "PROMOTED", "candidate_id": candidate_id,
        "evaluation_id": evaluation_id, "capability_id": "research.deep",
        "from_version": "1.0.0", "to_version": "1.1.0",
        "approver": "independent-approver", "evidence_refs": [ci_ref],
        "capability_digest": "new-cap-digest", "revision": 1,
        "previous_decision_digest": "boot-digest",
    }
    authority.records["new-cap-digest"] = ("CAPABILITY", new_capability)
    authority.records["promotion-digest"] = ("CAPABILITY_PROMOTION_DECISION", decision)
    return candidate_id, evaluation_id


def test_ci_evidence_requires_pinned_workflow_success_and_artifact_digest():
    store, _, _ = fixture()
    bad = ci_record()
    bad["workflow_path"] = ".github/workflows/untrusted.yml"
    with pytest.raises(EvolutionStoreError, match="pinned Firestore"):
        store.record_ci_evidence(bad, actor="ci")
    bad = ci_record()
    bad["jobs"] = [{"name": "firestore-emulator", "conclusion": "failure"}]
    with pytest.raises(EvolutionStoreError, match="successful conclusions"):
        store.record_ci_evidence(bad, actor="ci")
    bad = ci_record()
    bad["artifact_digests"] = []
    with pytest.raises(EvolutionStoreError, match="artifact digest"):
        store.record_ci_evidence(bad, actor="ci")


def test_candidate_and_evaluation_are_append_only_and_latest_evaluation_is_tracked():
    store, client, _ = fixture()
    ci = store.record_ci_evidence(ci_record(), actor="ci")
    candidate = store.propose_candidate({
        "record_type": "CAPABILITY_CANDIDATE", "capability_id": "research.deep",
        "base_version": "1.0.0", "candidate_version": "1.1.0",
        "proposer": "p", "source_commit": "c" * 40, "patch_digest": "e" * 64,
        "change_summary": "candidate", "evidence_refs": [ci["evidence_ref"]], "run_id": "r1",
    }, actor="ledger")
    first = store.evaluate_candidate({
        "candidate_id": candidate["record_id"], "evaluator": "e", "evaluator_version": "v1",
        "verdict": "PASS", "test_suite_digest": "f" * 64, "comparison_digest": "1" * 64,
        "evidence_refs": [ci["evidence_ref"]], "run_id": "r2",
    }, actor="ledger")
    second = store.evaluate_candidate({
        "candidate_id": candidate["record_id"], "evaluator": "e", "evaluator_version": "v1",
        "verdict": "FAIL", "test_suite_digest": "2" * 64, "comparison_digest": "3" * 64,
        "evidence_refs": [ci["evidence_ref"]], "run_id": "r3",
    }, actor="ledger")
    latest = client.data[f"aios_capability_latest_evaluations/{candidate['record_id']}"]
    assert latest["evaluation_id"] == second["evaluation_id"]
    assert latest["verdict"] == "FAIL"
    assert first["evaluation_id"] != second["evaluation_id"]


def test_signed_promotion_gate_atomically_advances_active_capability():
    store, _, authority = fixture()
    candidate_id, evaluation_id = prepare_promotion(store, authority)
    result = store.promote_candidate(
        candidate_id=candidate_id, evaluation_id=evaluation_id,
        decision_digest="promotion-digest", capability_digest="new-cap-digest",
        repository="yanhul/AIOS",
    )
    assert result["status"] == "ACTIVE"
    assert result["replayed"] is False
    active = store.get_active_capability("research.deep")
    assert active["pointer"]["version"] == "1.1.0"
    assert active["capability"]["candidate_id"] == candidate_id
    replay = store.promote_candidate(
        candidate_id=candidate_id, evaluation_id=evaluation_id,
        decision_digest="promotion-digest", capability_digest="new-cap-digest",
        repository="yanhul/AIOS",
    )
    assert replay["replayed"] is True


def test_promotion_rejects_latest_fail_even_when_older_pass_exists():
    store, _, authority = fixture()
    candidate_id, evaluation_id = prepare_promotion(store, authority)
    store.evaluate_candidate({
        "candidate_id": candidate_id, "evaluator": "independent-evaluator",
        "evaluator_version": "verifier@1", "verdict": "FAIL",
        "test_suite_digest": "2" * 64, "comparison_digest": "3" * 64,
        "evidence_refs": ["ci://CI-" + "0" * 64], "run_id": "later-fail",
    }, actor="ledger")
    with pytest.raises(EvolutionStoreError, match="latest candidate evaluation"):
        store.promote_candidate(candidate_id=candidate_id, evaluation_id=evaluation_id,
                                decision_digest="promotion-digest", capability_digest="new-cap-digest",
                                repository="yanhul/AIOS")


def test_promotion_rejects_ci_evidence_for_another_commit():
    store, _, authority = fixture()
    candidate_id, evaluation_id = prepare_promotion(store, authority, source_commit="c" * 40)
    # The signed authority artifacts remain valid but the repository binding differs.
    with pytest.raises(EvolutionStoreError, match="repository/commit"):
        store.promote_candidate(candidate_id=candidate_id, evaluation_id=evaluation_id,
                                decision_digest="promotion-digest", capability_digest="new-cap-digest",
                                repository="someone/else")


def test_proposer_evaluator_and_approver_must_be_distinct():
    store, _, authority = fixture()
    candidate_id, evaluation_id = prepare_promotion(store, authority)
    authority.records["promotion-digest"] = ("CAPABILITY_PROMOTION_DECISION", {
        **authority.records["promotion-digest"][1], "approver": "agent-proposer",
    })
    with pytest.raises(EvolutionStoreError, match="distinct"):
        store.promote_candidate(candidate_id=candidate_id, evaluation_id=evaluation_id,
                                decision_digest="promotion-digest", capability_digest="new-cap-digest",
                                repository="yanhul/AIOS")


def test_m10_pass_requires_exact_firestore_receipt_and_m11_evaluation_lineage():
    import hashlib

    store, client, _ = fixture()
    source_commit = "c" * 40
    ci = store.record_ci_evidence(ci_record(source_commit), actor="ci")
    ci_ref = ci["evidence_ref"]
    candidate = store.propose_candidate({
        "record_type": "CAPABILITY_CANDIDATE", "capability_id": "research.deep",
        "base_version": "1.0.0", "candidate_version": "1.1.0",
        "proposer": "candidate-author", "source_commit": source_commit,
        "patch_digest": "e" * 64, "change_summary": "verified lineage",
        "evidence_refs": [ci_ref], "run_id": "candidate-run",
    }, actor="ledger")
    evaluation = store.evaluate_candidate({
        "candidate_id": candidate["record_id"], "evaluator": "independent-verifier",
        "evaluator_version": "verifier@1", "verdict": "PASS",
        "test_suite_digest": "f" * 64, "comparison_digest": "1" * 64,
        "evidence_refs": [ci_ref], "run_id": "evaluation-run",
    }, actor="ledger")
    effect_id, attempt_id, receipt_id = "EF-1", "EF-1:attempt:1", "RC-1"
    lineage_digest = "a" * 64
    client.data["effects/EF-1"] = {
        "effect_id": effect_id, "attempt_id": attempt_id, "state": "OBSERVED_SUCCESS",
        "contract_id": "CT-1", "permit_id": "PM-1", "provider": "fixture-provider",
        "provider_operation_id": "OP-1", "provider_receipt_id": receipt_id,
        "execution_lineage": {"lineage": {"lineage_digest": lineage_digest}},
    }
    attempt_key = hashlib.sha256(attempt_id.encode()).hexdigest()
    client.data[f"effects/EF-1/attempts/{attempt_key}"] = {
        "effect_id": effect_id, "attempt_id": attempt_id, "state": "OBSERVED_SUCCESS",
        "provider": "fixture-provider", "provider_receipt_id": receipt_id,
    }
    client.data["provider_receipts/RC-1"] = {
        "record_type": "AIOS_TERMINAL_PROVIDER_RECEIPT", "receipt_id": receipt_id,
        "effect_id": effect_id, "attempt_id": attempt_id, "outcome": "OBSERVED_SUCCESS",
        "contract_id": "CT-1", "permit_id": "PM-1", "provider": "fixture-provider",
        "provider_operation_id": "OP-1",
        "authentication": {"algorithm": "Ed25519", "verified": True},
        "lineage_digest": lineage_digest,
    }
    record = {
        "record_type": "EXPERIENCE", "capability_id": "research.deep",
        "capability_version": "1.1.0", "task_id": "task-1", "outcome": "PASS",
        "contributor": "candidate-author", "evidence_refs": [
            "effect://EF-1", "attempt://EF-1/EF-1:attempt:1", "receipt://RC-1",
            "evaluation://" + evaluation["evaluation_id"], ci_ref,
        ], "run_id": "experience-run", "source_commit": source_commit,
        "artifact_digest": "2" * 64, "effect_id": effect_id,
        "attempt_id": attempt_id, "receipt_id": receipt_id,
        "verifier": "independent-verifier", "evaluation_id": evaluation["evaluation_id"],
        "verification_status": "VERIFIED_DIGITAL",
    }
    result = store.record_experience(record, actor="ledger")
    assert result["record_id"].startswith("XP-")

    client.data["provider_receipts/RC-1"]["attempt_id"] = "EF-1:attempt:2"
    with pytest.raises(EvolutionStoreError, match="verified terminal receipt"):
        store.record_experience({**record, "task_id": "task-2"}, actor="ledger")


def test_ci_run_attempt_is_single_immutable_evidence_identity():
    store, _, _ = fixture()
    first = ci_record()
    store.record_ci_evidence(first, actor="ci")
    changed = ci_record()
    changed["artifact_digests"] = [{"name": "firestore-emulator-1234", "id": 55,
                                    "size_in_bytes": 1024, "sha256": "a" * 64}]
    with pytest.raises(EvolutionStoreError, match="immutable evolution record/event conflict"):
        store.record_ci_evidence(changed, actor="ci")


def test_active_pointer_revision_must_match_signed_authority_decision():
    store, client, authority = fixture()
    candidate_id, evaluation_id = prepare_promotion(store, authority)
    store.promote_candidate(candidate_id=candidate_id, evaluation_id=evaluation_id,
                            decision_digest="promotion-digest", capability_digest="new-cap-digest",
                            repository="yanhul/AIOS")
    client.data["aios_active_capabilities/research.deep"]["revision"] = 0
    with pytest.raises(EvolutionStoreError, match="invalid signed promotion decision"):
        store.get_active_capability("research.deep")
