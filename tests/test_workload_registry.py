import pytest

from core.workload_registry import WorkloadRegistration, WorkloadRegistry


def registration(workload_id="yanhul/try@1", capability_id="try.research", version="1"):
    return WorkloadRegistration(
        workload_id=workload_id,
        capability_id=capability_id,
        version=version,
        adapter="aios/workload.json",
    )


def test_register_and_resolve_are_deterministic():
    registry = WorkloadRegistry()
    item = registration()
    registry.register(item.workload_id, item)
    assert registry.resolve(item.workload_id) == item
    assert list(registry.snapshot()) == [item.workload_id]


def test_duplicate_workload_and_capability_version_fail_closed():
    registry = WorkloadRegistry()
    first = registration()
    registry.register(first.workload_id, first)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(first.workload_id, first)
    with pytest.raises(ValueError, match="capability version already registered"):
        registry.register("other@1", registration("other@1", first.capability_id, "1"))


def test_capability_evolution_allows_distinct_immutable_versions():
    registry = WorkloadRegistry()
    v1 = registration("owner@1", "capability", "1")
    v2 = registration("owner@2", "capability", "2")
    registry.register(v1.workload_id, v1)
    registry.register(v2.workload_id, v2)
    assert registry.resolve("owner@1").version == "1"
    assert registry.resolve("owner@2").version == "2"


def test_unknown_workload_fails_closed():
    with pytest.raises(KeyError, match="unknown workload"):
        WorkloadRegistry().resolve("missing@1")


def test_registration_workload_identity_is_bound():
    with pytest.raises(ValueError, match="workload_id mismatch"):
        WorkloadRegistry().register("a@1", registration("b@1"))


def test_from_capability_entries_derives_discovery_only():
    registry = WorkloadRegistry.from_capability_entries([
        {"capability_id": "try.research", "version": "1", "owner": "yanhul/try", "manifest": "aios/workload.json"},
        {"capability_id": "android.assistant", "version": "1", "owner": "yanhul/android-ai-assistant", "manifest": "aios/workload.json"},
    ])
    assert len(registry) == 2
    assert registry.resolve("yanhul/try@1").capability_id == "try.research"
    assert registry.resolve("yanhul/android-ai-assistant@1").capability_id == "android.assistant"


def test_capability_entry_missing_or_invalid_metadata_fails_closed():
    with pytest.raises(ValueError, match="missing fields"):
        WorkloadRegistry.from_capability_entries([{"capability_id": "x", "version": "1", "owner": "o"}])
    with pytest.raises(ValueError, match="non-empty strings"):
        WorkloadRegistry.from_capability_entries([{"capability_id": "x", "version": "", "owner": "o", "manifest": "m"}])
