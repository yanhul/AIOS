from core.capability_catalog import load_catalog


def test_catalog_loads_registered_capabilities_and_edges():
    registry = load_catalog("capabilities/registry.yaml")
    assert registry.get("try.research") is not None
    assert registry.get("android.assistant") is not None
    assert registry.get("rx50.engineering") is not None


def test_catalog_edges_have_registered_endpoints():
    registry = load_catalog("capabilities/registry.yaml")
    for edge in registry.relationships():
        source_id, source_version = edge.source.rsplit("@", 1)
        target_id, target_version = edge.target.rsplit("@", 1)
        assert registry.get(source_id, source_version) is not None
        assert registry.get(target_id, target_version) is not None
