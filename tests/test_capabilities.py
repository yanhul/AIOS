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


def test_graph_rejects_relationship_without_evidence():
    try:
        CapabilityEdge("a@1", "requires", "b@1")
        assert False
    except CapabilityError as exc:
        assert "evidence" in str(exc)


def test_invalid_relation_and_unregistered_endpoint_fail_closed():
    registry = CapabilityRegistry()
    registry.register(cap("a"))
    try:
        registry.add_edge(CapabilityEdge("a@1", "unknown", "a@1", ("EV-1",)))
        assert False
    except CapabilityError:
        pass
    try:
        registry.add_edge(CapabilityEdge("a@1", "requires", "missing@1", ("EV-1",)))
        assert False
    except CapabilityError:
        pass


def test_registry_persists_and_reloads_through_aios_state(tmp_path):
    registry = CapabilityRegistry()
    a = cap("try.research", status="ACTIVE", inputs=("problem",), outputs=("evidence",))
    b = cap("try.verify", status="ACTIVE", inputs=("evidence",), outputs=("decision",))
    registry.register(a)
    registry.register(b)
    registry.add_edge(CapabilityEdge(a.key, "validated_by", b.key, ("EV-1",), "VERIFIED_DIGITAL"))

    committed = registry.persist(tmp_path, actor="test-suite")
    assert committed.endswith("capability_registry.json")

    restored = CapabilityRegistry.load(tmp_path)
    assert restored.get("try.research", "1") == a
    assert restored.relationships() == registry.relationships()
    assert restored.discover(required_inputs=("problem",), environment=None) == [a]


def test_registry_load_fails_closed_on_corrupt_state(tmp_path):
    path = tmp_path / "capabilities"
    path.mkdir()
    (path / "capability_registry.json").write_text("{broken", encoding="utf-8")
    try:
        CapabilityRegistry.load(tmp_path)
        assert False
    except CapabilityError as exc:
        assert "invalid capability registry JSON" in str(exc)


def test_contract_capabilities_must_resolve_to_registered_version(tmp_path):
    registry = CapabilityRegistry()
    registry.register(cap("try.research", status="ACTIVE"))
    contract = {"capabilities": ["try.research@1"]}
    assert registry.resolve_contract(contract)[0].key == "try.research@1"
    try:
        registry.resolve_contract({"capabilities": ["try.research"]})
        assert False
    except CapabilityError:
        pass
    try:
        registry.resolve_contract({"capabilities": ["missing@1"]})
        assert False
    except CapabilityError:
        pass


def test_contract_cannot_execute_candidate_capability():
    registry = CapabilityRegistry()
    registry.register(cap("candidate.work", status="CANDIDATE"))
    try:
        registry.resolve_contract({"capabilities": ["candidate.work@1"]})
        assert False
    except CapabilityError as exc:
        assert "not active" in str(exc)
