import pytest

from core.acceptance import AcceptancePredicate, evaluate_acceptance, evaluate_predicate
from core.finding import Finding


def test_finding_requires_machine_readable_fields_and_evidence():
    finding = Finding.from_mapping({
        "finding_id": "F-001",
        "severity": "BLOCKER",
        "location": "G3/net-index",
        "expected": "one authoritative net index",
        "observed": "two conflicting indices",
        "evidence_refs": [["EVIDENCE", "EV-123"]],
    })
    assert finding.as_record()["evidence_refs"] == [["EVIDENCE", "EV-123"]]


def test_finding_rejects_non_evidence_reference():
    with pytest.raises(ValueError):
        Finding.from_mapping({
            "finding_id": "F-001",
            "severity": "ERROR",
            "location": "x",
            "expected": "a",
            "observed": "b",
            "evidence_refs": [["ISSUE", "IS-1"]],
        })


def test_acceptance_eq_passes():
    p = AcceptancePredicate("A-1", "verification.outcome", "eq", "VERIFIED")
    result = evaluate_predicate(p, {"verification": {"outcome": "VERIFIED"}})
    assert result.passed is True


def test_acceptance_missing_path_fails_closed():
    p = AcceptancePredicate("A-1", "verification.outcome", "eq", "VERIFIED")
    result = evaluate_predicate(p, {"verification": {}})
    assert result.passed is False


def test_acceptance_unknown_operator_rejected():
    with pytest.raises(ValueError):
        AcceptancePredicate("A-1", "x", "execute_code", "anything")


def test_acceptance_requires_nonempty_unique_predicates():
    with pytest.raises(ValueError):
        evaluate_acceptance([], {})
    p1 = AcceptancePredicate("A-1", "x", "exists")
    p2 = AcceptancePredicate("A-1", "y", "exists")
    with pytest.raises(ValueError):
        evaluate_acceptance([p1, p2], {"x": 1, "y": 2})
