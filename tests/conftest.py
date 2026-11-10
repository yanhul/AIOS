"""Shared test configuration.

AIOS authority records (reconciliations, evaluations, receipts) are sealed
with a deployment secret. Tests run with a fixed test-only secret; tests that
exercise the "no key configured" path remove it explicitly.
"""
import pytest

from core.record_seal import SEAL_ENV


@pytest.fixture(autouse=True)
def _aios_record_seal_secret(monkeypatch):
    monkeypatch.setenv(SEAL_ENV, "aios-test-only-seal-secret")
