import pytest

from core.effect_authority import RETRY_KEYRING_ENV
from tests.retry_issuers import KEYRING_JSON


@pytest.fixture(autouse=True)
def _deployment_retry_keyring(monkeypatch):
    """Simulate the deployment-supplied retry issuer keyring (never in AIOS state)."""
    monkeypatch.setenv(RETRY_KEYRING_ENV, KEYRING_JSON)
