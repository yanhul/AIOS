from core.firestore_evolution_store import FirestoreEvolutionStore


class FakeReference:
    def __init__(self, project, collection, document_id):
        self.project = project
        self.collection_name = collection
        self.document_id = document_id


class FakeCollection:
    def __init__(self, project, name):
        self.project = project
        self.name = name

    def document(self, document_id):
        return FakeReference(self.project, self.name, document_id)


class FakeClient:
    def __init__(self, project):
        self.project = project

    def collection(self, name):
        return FakeCollection(self.project, name)


def test_ci_evidence_and_its_event_use_evidence_client_only():
    ledger = FakeClient("evolution-project")
    evidence = FakeClient("evidence-project")
    store = FirestoreEvolutionStore(
        ledger,
        project_id="evolution-project",
        authority_store=object(),
        trust_anchor={"pinned-key": {}},
        evidence_client=evidence,
        transaction_runner=lambda client, callback: None,
    )

    record = store._ref("aios_ci_evidence", "CI-1")
    event = store._ref("aios_ci_evidence_events", "event-1")
    candidate = store._ref("aios_capability_candidates", "CV-1")

    assert record.project == "evidence-project"
    assert event.project == "evidence-project"
    assert candidate.project == "evolution-project"



class MissingSnapshot:
    exists = False


class FakeTransaction:
    def __init__(self):
        self.created = []

    def get(self, reference):
        return MissingSnapshot()

    def create(self, reference, value):
        self.created.append((reference, value))


def test_ci_evidence_append_transaction_runs_only_on_evidence_client():
    ledger = FakeClient("evolution-project")
    evidence = FakeClient("evidence-project")
    calls = []
    tx = FakeTransaction()

    def transaction_runner(client, callback):
        calls.append(client)
        return callback(tx)

    store = FirestoreEvolutionStore(
        ledger,
        project_id="evolution-project",
        authority_store=object(),
        trust_anchor={"pinned-key": {}},
        evidence_client=evidence,
        transaction_runner=transaction_runner,
        expected_workflow_sha256="a" * 64,
    )
    result = store.record_ci_evidence({
        "repository": "yanhul/AIOS",
        "workflow_id": 1,
        "workflow_path": ".github/workflows/firestore-emulator.yml",
        "workflow_sha256": "a" * 64,
        "run_id": 2,
        "run_attempt": 1,
        "head_sha": "b" * 40,
        "event": "workflow_dispatch",
        "conclusion": "success",
        "jobs": [{"name": "firestore-emulator", "conclusion": "success"}],
        "artifact_digests": [{"name": "firestore-emulator-2", "sha256": "c" * 64}],
    }, actor="github-actions:ingestor")

    assert result["evidence_ref"].startswith("ci://CI-")
    assert calls == [evidence]
    assert len(tx.created) == 2
    assert {reference.project for reference, _ in tx.created} == {"evidence-project"}
    assert {reference.collection_name for reference, _ in tx.created} == {
        "aios_ci_evidence", "aios_ci_evidence_events"
    }
