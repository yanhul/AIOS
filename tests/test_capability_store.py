from core.capabilities import Capability, CapabilityEdge, CapabilityRegistry
from core.capability_store import CapabilityStore


def test_store_round_trip_preserves_registry(tmp_path):
    registry = CapabilityRegistry()
    a = Capability("a", "1", "test", "workload", inputs=("problem",), outputs=("artifact",), status="ACTIVE")
    b = Capability("b", "2", "test", "validator", inputs=("artifact",), outputs=("verdict",), status="ACTIVE")
    registry.register(a)
    registry.register(b)
    registry.add_edge(CapabilityEdge(a.key, "validated_by", b.key, ("evidence:1",), "VERIFIED_DIGITAL"))

    path = tmp_path / "capabilities.json"
    store = CapabilityStore(path)
    store.save(registry)
    restored = store.load()

    assert restored.snapshot() == registry.snapshot()


def test_store_missing_file_is_empty(tmp_path):
    registry = CapabilityStore(tmp_path / "missing.json").load()
    assert registry.snapshot() == {"capabilities": [], "edges": []}
