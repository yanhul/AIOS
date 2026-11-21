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
