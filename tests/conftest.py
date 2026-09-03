import pytest

from core.capabilities import Capability, CapabilityRegistry


@pytest.fixture(autouse=True)
def seed_authority_capabilities(tmp_path):
    registry = CapabilityRegistry()
    for name in ("research_is_validation", "fake-provider", "process-provider", "read", "write"):
        registry.register(Capability(name, "1", "test-fixture", "test", status="ACTIVE"))
    registry.persist(str(tmp_path), "test-fixture")
