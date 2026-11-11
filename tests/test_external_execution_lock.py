from __future__ import annotations

import pytest

from core.execution_lock import ExternalExecutionBlocked
from core.effect_authority import dispatch, _transition_dispatch
from core.runtime import (
    execute,
    execute_attempt,
    execute_retry_attempt,
    resume_attempt,
)


class CountingAdapter:
    name = "provider"

    def __init__(self):
        self.calls = 0

    def execute(self, **kwargs):
        self.calls += 1
        pytest.fail("provider must never be called while actor issuer is unavailable")


def test_initial_dispatch_is_blocked_before_filesystem_or_state_access(tmp_path):
    with pytest.raises(ExternalExecutionBlocked, match="independent actor issuer"):
        dispatch(str(tmp_path), "EF-missing", "owner", "attempt-1", "provider")
    assert not (tmp_path / "effects").exists()


def test_internal_dispatch_mutator_is_also_blocked(tmp_path):
    with pytest.raises(ExternalExecutionBlocked, match="independent actor issuer"):
        _transition_dispatch(
            str(tmp_path), "EF-forged", "owner",
            attempt=1, attempt_id="attempt-1", provider="provider",
        )
    assert not (tmp_path / "effects").exists()


@pytest.mark.parametrize(
    "invoke",
    [
        lambda td, adapter: execute(td, "contract", "permit", "operation", "actor", adapter),
        lambda td, adapter: execute_attempt(
            td, {}, {"state": "DISPATCHED"}, "actor", adapter, "attempt"
        ),
        lambda td, adapter: resume_attempt(
            td, {}, {"state": "DISPATCHED"}, "actor", adapter, object()
        ),
        lambda td, adapter: execute_retry_attempt(
            td, "contract", "permit", {"state": "UNKNOWN"}, "actor",
            adapter, "attempt-2", 2,
        ),
    ],
)
def test_every_public_provider_execution_entry_point_fails_closed(tmp_path, invoke):
    adapter = CountingAdapter()
    with pytest.raises(ExternalExecutionBlocked, match="independent actor issuer"):
        invoke(str(tmp_path), adapter)
    assert adapter.calls == 0
    assert not (tmp_path / "effects").exists()


def test_lock_has_no_environment_or_caller_controlled_override(monkeypatch):
    from core.execution_lock import require_external_execution_enabled

    monkeypatch.setenv("AIOS_EXTERNAL_EXECUTION_ENABLED", "1")
    monkeypatch.setenv("AIOS_ACTOR_ISSUER_VERIFIED", "1")
    with pytest.raises(ExternalExecutionBlocked):
        require_external_execution_enabled()
