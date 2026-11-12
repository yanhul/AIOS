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
# KEYRING_SPEC still contains an HMAC "minimind" entry on purpose: it must never
# be accepted for MiniMind (Ed25519-only, audit F-04.1).
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


# --- Ed25519 (MiniMind workload, audit F-04.1). Test-only deterministic keys. ---
def _ed25519_private(label):
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("utf-8")).digest())


def ed25519_private_pem(label="minimind-workload-test-key"):
    """PEM of a test workload private key (written to the workload's own key file by tests)."""
    from cryptography.hazmat.primitives import serialization
    return _ed25519_private(label).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption())


def ed25519_public_hex(label="minimind-workload-test-key"):
    from cryptography.hazmat.primitives import serialization
    return _ed25519_private(label).public_key().public_bytes(serialization.Encoding.Raw,
                                                              serialization.PublicFormat.Raw).hex()


def ed25519_keyring_spec(label="minimind-workload-test-key", provider="minimind", **extra):
    from core.provider_ed25519 import key_id_for
    pub = ed25519_public_hex(label)
    return {provider: {"key_id": key_id_for(pub), "public_key": pub, **extra}}


try:
    ED25519_PUBLIC_KEYRING_JSON = json.dumps(ed25519_keyring_spec())
except ImportError:  # cryptography absent: MiniMind receipts stay UNKNOWN (fail closed)
    ED25519_PUBLIC_KEYRING_JSON = None
