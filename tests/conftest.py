from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _allow_unit_runtime_paths_only(monkeypatch, request):
    """Exercise runtime/state-machine semantics without enabling deployed effects.

    The dedicated execution-lock tests deliberately do not receive this
    test-only seam. Production code has no environment or caller override.
    """
    if request.node.path.name == "test_external_execution_lock.py":
        return
    import core.runtime as runtime
    monkeypatch.setattr(runtime, "require_external_execution_enabled", lambda: None, raising=False)
    # runtime imports the gate locally at the enforcement point; patch the
    # source module only for tests that are explicitly exercising inner logic.
    import core.execution_lock as lock
    monkeypatch.setattr(lock, "require_external_execution_enabled", lambda: None)
