from __future__ import annotations

import pytest

from core.execution_lock import ExternalExecutionBlocked, require_external_execution_enabled
from core.runtime import execute_attempt, resume_attempt


class CountingAdapter:
    name = "provider"

    def __init__(self):
        self.calls = 0

    def execute(self, **kwargs):
        self.calls += 1
        pytest.fail("provider must never be called while actor issuer is unavailable")


def test_lock_is_unconditional_and_has_no_environment_override(monkeypatch):
    monkeypatch.setenv("AIOS_EXTERNAL_EXECUTION_ENABLED", "1")
    monkeypatch.setenv("AIOS_ACTOR_ISSUER_VERIFIED", "1")
    with pytest.raises(ExternalExecutionBlocked, match="independent actor issuer"):
        require_external_execution_enabled()


def test_execute_attempt_validates_bindings_then_blocks_before_provider():
    adapter = CountingAdapter()
    contract = {"capabilities": ["provider@1"], "allowed_effects": ["external_effect"]}
    effect = {
        "effect_id": "EF-test",
        "state": "DISPATCHED",
        "actor": "owner",
        "attempt_id": "EF-test:attempt:1",
    }
    with pytest.raises(ExternalExecutionBlocked, match="independent actor issuer"):
        execute_attempt("unused", contract, effect, "owner", adapter, effect["attempt_id"])
    assert adapter.calls == 0


def test_resume_blocks_before_external_runtime_or_provider(monkeypatch):
    import core.runtime as runtime

    adapter = CountingAdapter()
    class Runtime:
        calls = 0
        def resume(self, **kwargs):
            self.calls += 1
            pytest.fail("durable runtime must not be resumed while issuer is unavailable")

    contract = {"capabilities": ["provider@1"], "allowed_effects": ["external_effect"]}
    effect = {
        "effect_id": "EF-test",
        "state": "DISPATCHED",
        "actor": "owner",
        "attempt_id": "EF-test:attempt:1",
    }
    durable = Runtime()
    with pytest.raises(ExternalExecutionBlocked, match="independent actor issuer"):
        runtime.resume_attempt("unused", contract, effect, "owner", adapter, durable)
    assert durable.calls == 0
    assert adapter.calls == 0



def test_direct_subprocess_adapter_call_is_blocked_before_process_launch(monkeypatch):
    import subprocess
    from adapters.process import SubprocessAdapter

    def forbidden_run(*args, **kwargs):
        pytest.fail("subprocess provider must not launch without issuer")
    monkeypatch.setattr(subprocess, "run", forbidden_run)
    adapter = SubprocessAdapter("provider", ["python", "-c", "pass"])
    with pytest.raises(ExternalExecutionBlocked, match="independent actor issuer"):
        adapter.execute(contract={}, effect={"effect_id": "EF-x"}, attempt_id="EF-x:attempt:1")


def test_direct_repository_mutation_adapter_call_is_blocked_before_write(tmp_path):
    from core.repository_patch_adapter import RepositoryPatchAdapter

    adapter = RepositoryPatchAdapter(tmp_path)
    with pytest.raises(ExternalExecutionBlocked, match="independent actor issuer"):
        adapter.execute(
            contract={}, effect={"effect_id": "EF-x"}, attempt_id="EF-x:attempt:1"
        )
