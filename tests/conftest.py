"""Shared test configuration.

AIOS authority records (reconciliations, evaluations, receipts) are sealed
with a deployment secret. Tests run with a fixed test-only secret; tests that
exercise the "no key configured" path remove it explicitly.
"""
import pytest

from core.provider_trust import TRUST_ENV
from core.record_seal import SEAL_ENV
from tests.provider_trust_helpers import SECRET, SECRET_ENV, TRUST_JSON


@pytest.fixture(autouse=True)
def _aios_record_seal_secret(monkeypatch):
    monkeypatch.setenv(SEAL_ENV, "aios-test-only-seal-secret")
    # Provider source authenticity: only ``fake-provider`` has a trusted key.
    monkeypatch.setenv(TRUST_ENV, TRUST_JSON)
    monkeypatch.setenv(SECRET_ENV, SECRET)
