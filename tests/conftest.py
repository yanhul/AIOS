from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _allow_unlocked_runtime_paths_only(monkeypatch, request):
    """Opt-in seam for isolated state-machine/provider unit tests only.

    Tests that need successful inner runtime behavior must carry the explicit
    allow_unlocked_runtime marker. Unmarked tests, including security
    regressions and direct-entry tests, always use the real lock. This fixture
    is test-only and never changes production configuration.
    """
    if request.node.get_closest_marker("allow_unlocked_runtime") is None:
        return
    import core.execution_lock as lock
    monkeypatch.setattr(lock, "require_external_execution_enabled", lambda: None)
