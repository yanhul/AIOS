"""Deterministic Ed25519 fixture shared by TRY operation receipt tests."""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
PUBLIC_KEY_B64 = base64.b64encode(PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)).decode("ascii")


def sign_receipt(body, signed_fields):
    signed = {key: body[key] for key in signed_fields}
    import json
    payload = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    body["signature"] = base64.b64encode(PRIVATE_KEY.sign(payload)).decode("ascii")
    return body
