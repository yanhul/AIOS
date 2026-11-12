"""Test-only provider trust anchors: verifier keyring + provider-side signers."""
import json

from core.effect_authority import PROVIDER_RECEIPT_SCOPE, ProviderKeyring
from core.provider_authority import ProviderReceiptSigner, authenticate_receipt

PROVIDERS = ("fake-provider", "provider-1", "provider-2", "provider:test", "provider-a", "process-provider",
             "minimind", "kicad.eda", "repo_patch", "try.research", "android.assistant", "rx50.engineering")
SECRETS = {name: f"test-provider-signing-key::{name}" for name in PROVIDERS}
KEYRING_SPEC = {name: {"secret": secret, "scopes": [PROVIDER_RECEIPT_SCOPE]} for name, secret in SECRETS.items()}
KEYRING_SPEC["provider-revoked"] = {"secret": "revoked-provider-signing-key", "scopes": [PROVIDER_RECEIPT_SCOPE],
                                    "revoked": True}
KEYRING_JSON = json.dumps(KEYRING_SPEC)
# Provider-side environment of in-process adapters. "minimind" is deliberately
# absent: the MiniMind workload holds its own key and the AIOS parent must not.
SIGNING_KEYS_JSON = json.dumps({k: v for k, v in SECRETS.items() if k != "minimind"})
KEYRING = ProviderKeyring(KEYRING_SPEC)


def signer(name, secret=None, **kw):
    return ProviderReceiptSigner(name, secret or SECRETS[name], **kw)


def signed(receipt, effect, **kw):
    """Sign a ProviderReceipt as its (test) provider would."""
    return authenticate_receipt(receipt, effect, signer(receipt.provider), **kw)


def sign_observation(effect, obs, outcome="OBSERVED_SUCCESS", *, as_provider=None, secret=None, now=None, **kw):
    """Return ``obs`` with a provider receipt signature, as provider ``as_provider`` would sign it."""
    name = as_provider or obs["provider"]
    auth = signer(name, secret, **kw).sign(effect=effect, attempt_id=obs["attempt_id"],
                                           provider_operation_id=obs["provider_operation_id"],
                                           outcome=outcome, observation=obs["observation"], now=now)
    return {**obs, "authentication": auth}
