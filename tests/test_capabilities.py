from core.capabilities import Capability, CapabilityEdge, CapabilityError, CapabilityRegistry


def cap(cid, version="1", kind="workload", **kwargs):
    return Capability(cid, version, "test", kind, **kwargs)


def test_registry_registration_is_idempotent_and_versioned():
    registry = CapabilityRegistry()
    a = cap("try.research", inputs=("problem",), outputs=("report",), status="ACTIVE")
    assert registry.register(a) == a
    assert registry.register(a) == a
    assert registry.get("try.research", "1") == a


def test_discovery_is_contract_and_context_aware():
    registry = CapabilityRegistry()
    registry.register(cap(
        "android.action", kind="device", inputs=("command",), outputs=("result",),
        permissions=("android.control",), environments=("android",), status="ACTIVE",
    ))
    assert registry.discover(required_inputs=("command",), environment="android",
                             permission="android.control")
    assert not registry.discover(required_inputs=("command",), environment="linux")


def test_graph_requires_registered_nodes_and_preserves_evidence_level():
    registry = CapabilityRegistry()
    a = cap("rx50.design", status="ACTIVE")
    b = cap("rx50.verify", status="ACTIVE")
    registry.register(a)
    registry.register(b)
    edge = CapabilityEdge(a.key, "validated_by", b.key, ("evidence:erc-1",), "VERIFIED_DIGITAL")
    registry.add_edge(edge)
    assert registry.relationships(source=a.key, relation="validated_by")[0] == edge


def test_invalid_relation_and_unregistered_endpoint_fail_closed():
    registry = CapabilityRegistry()
    registry.register(cap("a"))
    try:
        registry.add_edge(CapabilityEdge("a@1", "unknown", "a@1"))
        assert False
    except CapabilityError:
        pass
    try:
        registry.add_edge(CapabilityEdge("a@1", "requires", "missing@1"))
        assert False
    except CapabilityError:
        pass
