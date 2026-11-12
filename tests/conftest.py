import pytest

from core.effect_authority import PROVIDER_KEYRING_ENV, RETRY_KEYRING_ENV
from core.provider_authority import PROVIDER_SIGNING_KEYS_ENV
from tests.provider_keys import KEYRING_JSON as PROVIDER_KEYRING_JSON, SIGNING_KEYS_JSON
from tests.retry_issuers import KEYRING_JSON


@pytest.fixture(autouse=True)
def _deployment_trust_anchors(monkeypatch):
    """Simulate deployment-supplied trust anchors (never stored in AIOS state)."""
    monkeypatch.setenv(RETRY_KEYRING_ENV, KEYRING_JSON)
    monkeypatch.setenv(PROVIDER_KEYRING_ENV, PROVIDER_KEYRING_JSON)
    # Provider-side signing keys: only test provider processes/adapters read these.
    monkeypatch.setenv(PROVIDER_SIGNING_KEYS_ENV, SIGNING_KEYS_JSON)
