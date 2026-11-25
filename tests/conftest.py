import pytest

from core.effect_authority import PROVIDER_KEYRING_ENV, RETRY_KEYRING_ENV
from core.provider_authority import PROVIDER_SIGNING_KEYS_ENV
from core.provider_ed25519 import ED25519_KEYRING_ENV
from tests.provider_keys import ED25519_PUBLIC_KEYRING_JSON, KEYRING_JSON as PROVIDER_KEYRING_JSON, SIGNING_KEYS_JSON
from tests.retry_issuers import KEYRING_JSON
try:  # jobs without cryptography run subsets that never authorize; authorize() then fails closed
    from tests.authority_keys import TRUSTED_KEYS_JSON, signer as _authority_test_signer
except ImportError:  # pragma: no cover
    TRUSTED_KEYS_JSON = _authority_test_signer = None
import core.authority as _authority


@pytest.fixture(autouse=True)
def _deployment_trust_anchors(monkeypatch):
    """Simulate deployment-supplied trust anchors (never stored in AIOS state)."""
    monkeypatch.setenv(RETRY_KEYRING_ENV, KEYRING_JSON)
    monkeypatch.setenv(PROVIDER_KEYRING_ENV, PROVIDER_KEYRING_JSON)
    monkeypatch.setenv(PROVIDER_SIGNING_KEYS_ENV, SIGNING_KEYS_JSON)
    # Ed25519 authority: verifier gets public keys via env; the test harness
    # plays the separate authority-signer process by registering a signer.
    monkeypatch.delenv("AIOS_AUTHORITY_SIGNING_KEY_FILE", raising=False)
    if TRUSTED_KEYS_JSON is not None:
        monkeypatch.setenv("AIOS_AUTHORITY_TRUSTED_KEYS", TRUSTED_KEYS_JSON)
        monkeypatch.setattr(_authority, "_process_signer", _authority_test_signer())
    monkeypatch.setenv("AIOS_EVIDENCE_SIGNING_SECRET", "unit-test-evidence-secret-32")
    if ED25519_PUBLIC_KEYRING_JSON is not None:
        monkeypatch.setenv(ED25519_KEYRING_ENV, ED25519_PUBLIC_KEYRING_JSON)


@pytest.fixture(autouse=True)
def _isolate_absorption_artifacts(tmp_path, monkeypatch):
    """Keep pytest and nested pytest runs from writing into tracked research artifacts."""
    outputs = (
        "AIOS_ABSORPTION_OUT",
        "AIOS_ABSORPTION_VERIFY",
        "AIOS_ABSORPTION_EXECUTOR_OUT",
        "AIOS_ABSORPTION_VERIFY_OUT",
        "AIOS_ABSORPTION_PROMOTION_OUT",
        "AIOS_ABSORPTION_RUNTIME_PROOF_OUT",
        "AIOS_ABSORPTION_REPAIR_OUT",
        "AIOS_ABSORPTION_OUTCOME",
    )
    for name in outputs:
        monkeypatch.setenv(name, str(tmp_path / (name.lower() + ".json")))
