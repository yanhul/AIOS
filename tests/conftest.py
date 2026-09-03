import pytest

from core.capabilities import Capability, CapabilityRegistry


@pytest.fixture(autouse=True)
def seed_authority_capabilities(request):
    tmp_path = request.node.funcargs.get("tmp_path")
    if tmp_path is None:
        return
    registry = CapabilityRegistry()
    for name in ("research_is_validation", "fake-provider", "process-provider", "read", "write"):
        registry.register(Capability(name, "1", "test-fixture", "test", status="ACTIVE"))
    registry.persist(str(tmp_path), "test-fixture")
