"""NON-PRODUCTION Ed25519 authority keys for unit tests only (fixed seeds)."""
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.attestation import AuthoritySigner, key_id_for

TEST_SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))


def signer(key=TEST_SIGNING_KEY) -> AuthoritySigner:
    return AuthoritySigner(key)


def keyring_json(*entries) -> str:
    """entries: (AuthoritySigner, status) pairs."""
    keys = {s.key_id: {"public_key": s.public_key_hex(), "status": status} for s, status in entries}
    return json.dumps({"version": 1, "keys": keys})


TRUSTED_KEYS_JSON = keyring_json((signer(), "active"))
