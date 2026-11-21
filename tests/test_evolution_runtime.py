import pytest

from core.evolution_runtime import (
    EvolutionRuntimeBlocked, FirestoreEvolutionService,
    create_firestore_evolution_service,
)


class Store:
    def __init__(self):
        self.calls = []

    def record_experience(self, record, *, actor):
        self.calls.append(("experience", record, actor))
        return {"record_id": "XP-test"}

    def propose_candidate(self, record, *, actor):
        self.calls.append(("candidate", record, actor))
        return {"record_id": "CV-test"}

    def evaluate_candidate(self, record, *, actor):
        self.calls.append(("evaluation", record, actor))
        return {"evaluation_id": "CE-test"}


def test_firestore_service_routes_m10_and_m11_to_store():
    store = Store()
    service = FirestoreEvolutionService(store, actor="aios-runtime")
    assert service.record_experience(outcome="BLOCKED")["record_id"] == "XP-test"
    assert service.propose_candidate(capability_id="x")["record_id"] == "CV-test"
    assert service.evaluate_candidate(candidate_id="CV-test")["evaluation_id"] == "CE-test"
    assert [item[0] for item in store.calls] == ["experience", "candidate", "evaluation"]
    assert all(item[2] == "aios-runtime" for item in store.calls)
    assert store.calls[0][1]["record_type"] == "EXPERIENCE"
    assert store.calls[1][1]["record_type"] == "CAPABILITY_CANDIDATE"


def test_firestore_runtime_refuses_local_fallback():
    with pytest.raises(EvolutionRuntimeBlocked, match="no local fallback"):
        create_firestore_evolution_service(
            environ={"AIOS_EVOLUTION_BACKEND": "filesystem"}, actor="test",
        )


def test_firestore_runtime_requires_project_and_explicit_backend():
    with pytest.raises(EvolutionRuntimeBlocked, match="PROJECT_ID"):
        create_firestore_evolution_service(
            environ={"AIOS_EVOLUTION_BACKEND": "firestore"}, actor="test",
        )


def test_firestore_runtime_requires_reviewed_ci_workflow_pin():
    with pytest.raises(EvolutionRuntimeBlocked, match="WORKFLOW_SHA256"):
        create_firestore_evolution_service(
            environ={"AIOS_EVOLUTION_BACKEND": "firestore", "AIOS_FIRESTORE_PROJECT_ID": "test"},
            actor="test",
        )
