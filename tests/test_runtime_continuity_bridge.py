import pytest

from core.runtime import validate_runtime_continuity
from core.runtime_continuity import ContinuityCheckpoint, ContinuityError, RuntimeIdentity


def checkpoint(pending=None):
    return ContinuityCheckpoint(
        execution_id="exec-1",
        policy_digest="policy-a",
        capability_id="cap-x",
        capability_version="1",
        step=4,
        attempt=2,
        pending_effect_id=pending,
        runtime=RuntimeIdentity("runtime-a", "provider-a", "1"),
    )


def test_runtime_bridge_preserves_authority_on_replacement():
    validate_runtime_continuity(
        checkpoint(),
        execution_id="exec-1",
        policy_digest="policy-a",
        capability_id="cap-x",
        capability_version="1",
        replacement=RuntimeIdentity("runtime-b", "provider-b", "2"),
    )


def test_runtime_bridge_blocks_policy_drift():
    with pytest.raises(ContinuityError):
        validate_runtime_continuity(
            checkpoint(),
            execution_id="exec-1",
            policy_digest="policy-b",
            capability_id="cap-x",
            capability_version="1",
            replacement=RuntimeIdentity("runtime-b", "provider-b", "2"),
        )


def test_runtime_bridge_requires_pending_effect_binding():
    with pytest.raises(ContinuityError):
        validate_runtime_continuity(
            checkpoint("effect-9"),
            execution_id="exec-1",
            policy_digest="policy-a",
            capability_id="cap-x",
            capability_version="1",
            replacement=RuntimeIdentity("runtime-b", "provider-b", "2"),
        )

    validate_runtime_continuity(
        checkpoint("effect-9"),
        execution_id="exec-1",
        policy_digest="policy-a",
        capability_id="cap-x",
        capability_version="1",
        replacement=RuntimeIdentity("runtime-b", "provider-b", "2"),
        effect={"effect_id": "effect-9"},
    )
