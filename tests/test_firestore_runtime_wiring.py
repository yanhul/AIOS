import pytest

from core.runtime import execute, execute_attempt, execute_retry_attempt, resume_attempt


class Adapter:
    name = "test-provider"


def test_production_execute_refuses_filesystem_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOS_REQUIRE_FIRESTORE_EFFECT_STORE", "true")
    with pytest.raises(RuntimeError, match="no filesystem fallback"):
        execute(str(tmp_path), "contract", "permit", "operation", "actor", Adapter())


def test_production_resume_requires_firestore_store(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOS_REQUIRE_FIRESTORE_EFFECT_STORE", "true")
    with pytest.raises(RuntimeError, match="no filesystem fallback"):
        resume_attempt(str(tmp_path), {}, {}, "actor", Adapter())


def test_production_low_level_filesystem_execution_is_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOS_REQUIRE_FIRESTORE_EFFECT_STORE", "true")
    with pytest.raises(RuntimeError, match="filesystem-backed execute_attempt is disabled"):
        execute_attempt(str(tmp_path), {}, {}, "actor", Adapter(), "attempt")


def test_production_retry_remains_blocked(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOS_REQUIRE_FIRESTORE_EFFECT_STORE", "true")
    with pytest.raises(RuntimeError, match="retry is disabled"):
        execute_retry_attempt(str(tmp_path), "contract", "permit", {}, "actor",
                              Adapter(), "attempt-2", 2)
