# AIOS-CONTRACT: Capability registration is descriptive; only ACTIVE capabilities may resolve into authority-bearing contracts.
# AIOS-REGRESSION: A registered CANDIDATE must remain discoverable but must fail require() and resolve_contract().
# AIOS-OWNER: AIOS capability registry and authority boundary.
# AIOS-COVERAGE-GAP: Previously CANDIDATE status was accepted by require(), allowing unpromoted capability references into contracts.
# AIOS-BASELINE: Existing ACTIVE capability resolution, version pinning, persistence, and DEPRECATED rejection must remain unchanged.
from pathlib import Path

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
    registry.register(cap("a", status="ACTIVE"))
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


def test_candidate_capability_is_discoverable_but_not_authorizable():
    registry = CapabilityRegistry()
    candidate = cap("repo_patch", status="CANDIDATE")
    registry.register(candidate)

    # Discovery is descriptive; it must not be confused with authority.
    assert registry.discover(kind="workload") == [candidate]
    try:
        registry.require(candidate.key)
        assert False, "candidate capability must not cross the authority boundary"
    except CapabilityError as exc:
        assert "not promoted ACTIVE" in str(exc)


def test_contract_resolution_rejects_candidate_and_deprecated_capabilities():
    registry = CapabilityRegistry()
    registry.register(cap("candidate.workload", status="CANDIDATE"))
    registry.register(cap("old.workload", status="DEPRECATED"))

    for key in ("candidate.workload@1", "old.workload@1"):
        try:
            registry.resolve_contract({"capabilities": [key]})
            assert False, f"{key} must not authorize a contract"
        except CapabilityError:
            pass


def test_shipped_repo_patch_capability_is_registered_but_not_promoted():
    registry = CapabilityRegistry.load(Path(__file__).resolve().parents[1])
    candidate = registry.get("repo_patch", "1")
    assert candidate is not None
    assert candidate.status == "CANDIDATE"
    assert "persisted OBSERVED_SUCCESS effect" in candidate.evidence_requirements
    assert "governance promotion decision" in candidate.evidence_requirements
    try:
        registry.resolve_contract({"capabilities": ["repo_patch@1"]})
        assert False, "repo_patch must remain unauthorized until independently promoted"
    except CapabilityError as exc:
        assert "not promoted ACTIVE" in str(exc)


def test_registry_load_rejects_non_object_root_and_wrong_collection_types(tmp_path):
    path = tmp_path / "capabilities"
    path.mkdir()
    registry_file = path / "capability_registry.json"
    for payload, expected in (
        ("[]", "root must be an object"),
        ('{"schema_version":1,"capabilities":{},"edges":[]}', "must be lists"),
        ('{"schema_version":1,"capabilities":[],"edges":{}}', "must be lists"),
    ):
        registry_file.write_text(payload, encoding="utf-8")
        try:
            CapabilityRegistry.load(tmp_path)
            assert False, f"malformed registry must fail closed: {payload}"
        except CapabilityError as exc:
            assert expected in str(exc)


def test_registry_load_rejects_string_instead_of_sequence_fields(tmp_path):
    path = tmp_path / "capabilities"
    path.mkdir()
    registry_file = path / "capability_registry.json"
    registry_file.write_text(
        '{"schema_version":1,"capabilities":[{"capability_id":"x","version":"1",'
        '"owner":"test","kind":"workload","inputs":"repository.patch"}],"edges":[]}',
        encoding="utf-8",
    )
    try:
        CapabilityRegistry.load(tmp_path)
        assert False, "string fields must not be silently split into characters"
    except CapabilityError as exc:
        assert "inputs must be a list" in str(exc)


def test_registry_load_rejects_duplicate_capability_records(tmp_path):
    path = tmp_path / "capabilities"
    path.mkdir()
    item = '{"capability_id":"x","version":"1","owner":"test","kind":"workload","status":"CANDIDATE"}'
    (path / "capability_registry.json").write_text(
        '{"schema_version":1,"capabilities":[' + item + ',' + item + '],"edges":[]}',
        encoding="utf-8",
    )
    try:
        CapabilityRegistry.load(tmp_path)
        assert False, "duplicate records must not be silently accepted"
    except CapabilityError as exc:
        assert "duplicate capability record" in str(exc)


def test_registry_load_rejects_malformed_edge_types_as_capability_error(tmp_path):
    path = tmp_path / "capabilities"
    path.mkdir()
    (path / "capability_registry.json").write_text(
        '{"schema_version":1,"capabilities":[],"edges":[{"source":"x@1",'
        '"relation":[],"target":"y@1"}]}',
        encoding="utf-8",
    )
    try:
        CapabilityRegistry.load(tmp_path)
        assert False, "malformed edge types must fail closed"
    except CapabilityError as exc:
        assert "must be non-empty strings" in str(exc)
