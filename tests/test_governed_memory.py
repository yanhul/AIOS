import pytest

from core.governed_memory import (
    build_memory_record,
    retrieve_memory,
    validate_memory_record,
)


def record(**kwargs):
    return build_memory_record(
        memory_type="SEMANTIC",
        content={"fact": "schematic evidence is required"},
        evidence_refs=[["EVIDENCE", "EV-1"]],
        predecessor="decision-1",
        authority="AIOS_CONTROL_PLANE",
        source_commit="abc",
        **kwargs,
    ).as_dict()


def test_memory_requires_governed_lineage():
    with pytest.raises(ValueError, match="evidence_refs"):
        build_memory_record(
            memory_type="SEMANTIC",
            content={"fact": "x"},
            evidence_refs=[],
            predecessor="decision-1",
            authority="AIOS_CONTROL_PLANE",
            source_commit="abc",
        )


def test_memory_authority_is_control_plane_only():
    with pytest.raises(ValueError, match="authority"):
        build_memory_record(
            memory_type="SEMANTIC",
            content={"fact": "x"},
            evidence_refs=[["EVIDENCE", "EV-1"]],
            predecessor="d1",
            authority="REASONER",
            source_commit="abc",
        )


def test_memory_identity_is_self_bound():
    item = record()
    validate_memory_record(item)
    item["content"]["fact"] = "forged"
    with pytest.raises(ValueError, match="identity"):
        validate_memory_record(item)


def test_memory_retrieval_returns_candidate_not_authority():
    item = record()
    found = retrieve_memory([item], query="schematic", current_commit="abc")
    assert len(found) == 1
    assert found[0]["context_role"] == "MEMORY_CANDIDATE"
    assert found[0]["authority"] == "NONE"


def test_prior_commit_memory_remains_a_candidate_with_lineage():
    item = record(source_commit="old")
    found = retrieve_memory([item], query="schematic", current_commit="abc")
    assert len(found) == 1
    assert found[0]["source_commit"] == "old"
    assert found[0]["authority"] == "NONE"


def test_revoked_memory_is_not_retrieved():
    item = record(status="REVOKED")
    assert retrieve_memory([item], query="schematic", current_commit="abc") == []


def test_tampered_memory_id_is_blocked():
    item = record()
    item["memory_id"] = "MEM-forged"
    with pytest.raises(ValueError, match="identity"):
        validate_memory_record(item)
