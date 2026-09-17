import pytest

from core.evidence import EvidenceRecord
from core.runtime import ProviderReceipt, validate_receipt


BASE_EFFECT = {
    "effect_id": "EF-1",
    "state": "DISPATCHED",
    "attempt_id": "EF-1:attempt:1",
    "provider": "fake-provider",
    "target_sha": "abc123",
    "evidence_ref": "EV-1",
    "lineage_ref": "LIN-1",
    "idempotency_key": "idem-1",
    "attempt_fence": 7,
}


def _evidence(evidence_id="EV-1"):
    return EvidenceRecord(
        evidence_id=evidence_id,
        level="OBSERVED",
        source_ref="test://gate1",
        claim="provider observed terminal outcome",
        run_id="run-1",
        provider="fake-provider",
    ).as_record()


def receipt(**overrides):
    values = {
        "provider": "fake-provider",
        "effect_id": "EF-1",
        "attempt_id": "EF-1:attempt:1",
        "provider_operation_id": "provider-op-1",
        "outcome": "OBSERVED_SUCCESS",
        "observation": {"status": "ok", "evidence": _evidence()},
        "target_sha": "abc123",
        "evidence_ref": "EV-1",
        "lineage_ref": "LIN-1",
        "idempotency_key": "idem-1",
        "attempt_fence": 7,
    }
    values.update(overrides)
    return ProviderReceipt(**values)


def test_gate1_accepts_fully_bound_receipt():
    validate_receipt(receipt(), BASE_EFFECT, "EF-1:attempt:1", "fake-provider")


@pytest.mark.parametrize(
    "field, value, message",
    [
        ("effect_id", "EF-wrong", "effect binding mismatch"),
        ("attempt_id", "EF-1:attempt:2", "attempt binding mismatch"),
        ("provider", "other-provider", "provider binding mismatch"),
        ("target_sha", "wrong-sha", "target_sha binding mismatch"),
        ("evidence_ref", "EV-wrong", "evidence_ref binding mismatch"),
        ("lineage_ref", "LIN-wrong", "lineage_ref binding mismatch"),
        ("idempotency_key", "idem-wrong", "idempotency_key binding mismatch"),
        ("attempt_fence", 8, "attempt_fence binding mismatch"),
    ],
)
def test_gate1_rejects_binding_mismatch(field, value, message):
    with pytest.raises(ValueError, match=message):
        validate_receipt(receipt(**{field: value}), BASE_EFFECT, "EF-1:attempt:1", "fake-provider")


@pytest.mark.parametrize(
    "field, value",
    [
        ("target_sha", ""),
        ("evidence_ref", ""),
        ("lineage_ref", ""),
        ("idempotency_key", ""),
        ("provider_operation_id", ""),
    ],
)
def test_gate1_rejects_missing_required_text(field, value):
    with pytest.raises(ValueError):
        validate_receipt(receipt(**{field: value}), BASE_EFFECT, "EF-1:attempt:1", "fake-provider")


def test_gate1_rejects_missing_target_on_effect():
    effect = dict(BASE_EFFECT)
    effect.pop("target_sha")
    with pytest.raises(ValueError, match="effect target_sha"):
        validate_receipt(receipt(), effect, "EF-1:attempt:1", "fake-provider")


def test_gate1_rejects_missing_fence_on_effect():
    effect = dict(BASE_EFFECT)
    effect.pop("attempt_fence")
    with pytest.raises(ValueError, match="effect attempt_fence"):
        validate_receipt(receipt(), effect, "EF-1:attempt:1", "fake-provider")


def test_gate1_rejects_invalid_fence_type():
    with pytest.raises(ValueError, match="attempt_fence"):
        validate_receipt(receipt(attempt_fence=True), BASE_EFFECT, "EF-1:attempt:1", "fake-provider")


def test_gate1_rejects_negative_fence():
    with pytest.raises(ValueError, match="attempt_fence"):
        validate_receipt(receipt(attempt_fence=-1), BASE_EFFECT, "EF-1:attempt:1", "fake-provider")


def test_gate1_rejects_non_terminal_outcome():
    with pytest.raises(ValueError, match="terminal outcome"):
        validate_receipt(receipt(outcome="UNKNOWN"), BASE_EFFECT, "EF-1:attempt:1", "fake-provider")


def test_gate1_rejects_mismatched_nested_evidence_identity():
    with pytest.raises(ValueError, match="evidence identity binding"):
        validate_receipt(
            receipt(observation={"status": "ok", "evidence": _evidence("EV-OTHER")}),
            BASE_EFFECT,
            "EF-1:attempt:1",
            "fake-provider",
        )


def test_gate1_receipt_is_frozen():
    item = receipt()
    with pytest.raises(AttributeError):
        item.effect_id = "EF-wrong"
