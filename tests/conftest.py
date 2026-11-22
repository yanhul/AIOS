import sys

if sys.version_info < (3, 12):
    raise RuntimeError("AIOS requires Python 3.12+ (see pyproject.toml)")

import pytest

from core.effect_authority import PROVIDER_KEYRING_ENV, RETRY_KEYRING_ENV
from core.provider_authority import PROVIDER_SIGNING_KEYS_ENV
from core.provider_ed25519 import ED25519_KEYRING_ENV
from tests.provider_keys import ED25519_PUBLIC_KEYRING_JSON, KEYRING_JSON as PROVIDER_KEYRING_JSON, SIGNING_KEYS_JSON
from tests.retry_issuers import KEYRING_JSON


@pytest.fixture(autouse=True)
def _deployment_trust_anchors(monkeypatch):
    """Simulate deployment-supplied trust anchors (never stored in AIOS state)."""
    monkeypatch.setenv(RETRY_KEYRING_ENV, KEYRING_JSON)
    monkeypatch.setenv(PROVIDER_KEYRING_ENV, PROVIDER_KEYRING_JSON)
    monkeypatch.setenv(PROVIDER_SIGNING_KEYS_ENV, SIGNING_KEYS_JSON)
    monkeypatch.setenv("AIOS_AUTHORITY_ATTESTATION_SECRET", "unit-test-authority-secret-32")
    monkeypatch.setenv("AIOS_EVIDENCE_SIGNING_SECRET", "unit-test-evidence-secret-32")
    if ED25519_PUBLIC_KEYRING_JSON is not None:
        monkeypatch.setenv(ED25519_KEYRING_ENV, ED25519_PUBLIC_KEYRING_JSON)


_RESEARCH_OUTPUT_ENVS = (
    "AIOS_RESEARCH_OUT", "AIOS_ABSORPTION_OUT", "AIOS_ABSORPTION_EXECUTOR_OUT",
    "AIOS_ABSORPTION_VERIFY_OUT", "AIOS_ABSORPTION_PROMOTION_OUT", "AIOS_ABSORPTION_REPAIR_OUT",
    "AIOS_ABSORPTION_RUNTIME_PROOF_OUT", "AIOS_ABSORPTION_OUTCOME",
)


@pytest.fixture(autouse=True)
def _isolated_research_outputs(monkeypatch, tmp_path):
    """Keep tracked research/artifacts/*.json untouched by the test suite."""
    out = tmp_path / "research-artifacts"
    for name in _RESEARCH_OUTPUT_ENVS:
        monkeypatch.setenv(name, str(out / (name.lower() + ".json")))
