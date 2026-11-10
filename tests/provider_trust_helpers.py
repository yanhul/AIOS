"""Test-only provider signer for ``core.provider_trust`` (PR #126 @18ec11f P1).

``conftest`` trusts one HMAC key for ``fake-provider``. Fake providers sign with
it exactly as a real provider would; attackers in tests sign with anything else.
"""
import json

from core.provider_trust import OBSERVED, RECONCILED_PREFIX, attestation_payload, sign_attestation

FAKE_PROVIDER = "fake-provider"
KEY_ID = "test-fake-provider-k1"
SECRET_ENV = "AIOS_TEST_FAKE_PROVIDER_SECRET"
SECRET = "aios-test-only-fake-provider-secret"
# Provider names used by the existing effect-authority suites; all share the test key.
TRUSTED_TEST_PROVIDERS = (FAKE_PROVIDER, "provider-a", "provider-1", "provider:test")
TRUST_JSON = json.dumps({"providers": {
    name: [{"key_id": KEY_ID, "algorithm": "HMAC-SHA256", "secret_env": SECRET_ENV}]
    for name in TRUSTED_TEST_PROVIDERS}})


def sign_observation(*, provider, effect_id, attempt_id, outcome, provider_operation_id, evidence,
                     observation=None, secret=SECRET, key_id=KEY_ID):
    payload = attestation_payload(provider=provider, effect_id=effect_id, attempt_id=attempt_id,
                                  statement=OBSERVED, evidence=evidence, outcome=outcome,
                                  provider_operation_id=provider_operation_id, observation=observation)
    return sign_attestation(payload, key_id=key_id, secret=secret)


def sign_reconciliation(effect, verdict, evidence, outcome=None, *, secret=SECRET, key_id=KEY_ID):
    payload = attestation_payload(provider=effect["provider"], effect_id=effect["effect_id"],
                                  attempt_id=effect["attempt_id"], statement=RECONCILED_PREFIX + verdict,
                                  evidence=evidence, outcome=outcome if verdict == "APPLIED" else None)
    return sign_attestation(payload, key_id=key_id, secret=secret)


def signed_receipt(provider, effect_id, attempt_id, provider_operation_id, outcome="OBSERVED_SUCCESS",
                   observation=None):
    """A ProviderReceipt carrying provider evidence and a trusted-key attestation."""
    from core.evidence import EvidenceRecord
    from core.runtime import ProviderReceipt
    ev = EvidenceRecord(evidence_id=f"EV-{provider_operation_id}", level="OBSERVED",
                        source_ref=f"provider://{provider}/ops/{provider_operation_id}",
                        claim="provider executed operation", run_id=attempt_id, provider=provider).as_record()
    obs = {**(observation or {"status": "ok"}), "evidence": ev}
    att = sign_observation(provider=provider, effect_id=effect_id, attempt_id=attempt_id, outcome=outcome,
                           provider_operation_id=provider_operation_id, evidence=ev, observation=obs)
    return ProviderReceipt(provider=provider, effect_id=effect_id, attempt_id=attempt_id,
                           provider_operation_id=provider_operation_id, outcome=outcome,
                           observation=obs, attestation=att)


def attested(provider_observation, effect_id, outcome="OBSERVED_SUCCESS"):
    """Return ``provider_observation`` plus the provider's trusted-key attestation over it."""
    po = dict(provider_observation)
    po["attestation"] = sign_observation(
        provider=po["provider"], effect_id=effect_id, attempt_id=po["attempt_id"], outcome=outcome,
        provider_operation_id=po.get("provider_operation_id"), evidence=po["evidence"],
        observation=po.get("observation"))
    return po
