from core.runtime_continuity import (
    ContinuityCheckpoint,
    ContinuityError,
    RuntimeIdentity,
    validate_runtime_replacement,
)


def _checkpoint(pending_effect_id=None):
    return ContinuityCheckpoint(
        execution_id="exec-1",
        policy_digest="policy-a",
        capability_id="cap-x",
        capability_version="1",
        step=3,
        attempt=2,
        pending_effect_id=pending_effect_id,
        runtime=RuntimeIdentity("runtime-a", "provider-a", "1"),
    )


def test_provider_replacement_preserves_aios_authority_identity():
    validate_runtime_replacement(
        _checkpoint(),
        execution_id="exec-1",
        policy_digest="policy-a",
        capability_id="cap-x",
        capability_version="1",
        replacement=RuntimeIdentity("runtime-b", "provider-b", "2"),
    )


def test_replacement_cannot_change_policy_or_capability():
    try:
        validate_runtime_replacement(
            _checkpoint(),
            execution_id="exec-1",
            policy_digest="policy-b",
            capability_id="cap-x",
            capability_version="1",
            replacement=RuntimeIdentity("runtime-b", "provider-b", "2"),
        )
    except ContinuityError:
        return
    raise AssertionError("policy drift must block runtime replacement")


def test_pending_effect_requires_explicit_reconciliation():
    try:
        validate_runtime_replacement(
            _checkpoint("effect-7"),
            execution_id="exec-1",
            policy_digest="policy-a",
            capability_id="cap-x",
            capability_version="1",
            replacement=RuntimeIdentity("runtime-b", "provider-b", "2"),
        )
    except ContinuityError:
        return
    raise AssertionError("pending effect migration must fail closed")


def test_pending_effect_can_be_bound_for_reconciliation():
    validate_runtime_replacement(
        _checkpoint("effect-7"),
        execution_id="exec-1",
        policy_digest="policy-a",
        capability_id="cap-x",
        capability_version="1",
        replacement=RuntimeIdentity("runtime-b", "provider-b", "2"),
        effect={"effect_id": "effect-7"},
    )
