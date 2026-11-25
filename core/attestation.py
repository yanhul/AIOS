"""Asymmetric (Ed25519) authority attestation for AIOS execution permits.

Trust boundary
--------------
* ``AuthoritySigner`` holds the Ed25519 *private* key. It runs only in the
  authority-signer process (``scripts/aios_authority_signer.py``) and loads the
  key from a file named by ``AIOS_AUTHORITY_SIGNING_KEY_FILE``.
* ``AuthorityVerifier`` holds *public* keys only (``AIOS_AUTHORITY_TRUSTED_KEYS``).
  It can verify attestations and cannot produce them.
* Execution runtimes call ``authorize()``, which uses the verifier and refuses
  to run in a process configured with signing material.

There is no HMAC path. Legacy ``HMAC-SHA256`` attestations (version 1) are
rejected after cutover and must be re-issued by the authority signer.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from typing import Mapping

from .contract import verify_permit
from .mutation import canonical_json

try:  # without the library both signing and verification fail closed
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:  # pragma: no cover
    InvalidSignature = serialization = Ed25519PrivateKey = Ed25519PublicKey = None

ATTESTATION_TYPE = "EXECUTION_PERMIT_ATTESTATION"
ATTESTATION_VERSION = 2
ALGORITHM = "Ed25519"
LEGACY_ALGORITHM = "HMAC-SHA256"
SIGNING_KEY_FILE_ENV = "AIOS_AUTHORITY_SIGNING_KEY_FILE"
TRUSTED_KEYS_ENV = "AIOS_AUTHORITY_TRUSTED_KEYS"
LEGACY_SECRET_ENV = "AIOS_AUTHORITY_ATTESTATION_SECRET"
_DOMAIN = b"AIOS-EXECUTION-PERMIT-ATTESTATION-V2\x00"
_FIELDS = frozenset({"attestation_type", "version", "algorithm", "key_id",
                     "contract_id", "permit_id", "issuer", "signature"})
_KEY_ID = re.compile(r"ed25519:[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_KEY_STATUSES = frozenset({"active", "revoked"})


class AttestationError(ValueError):
    """Raised for every attestation/key failure; messages never include key material."""


def _require_crypto() -> None:
    if Ed25519PublicKey is None:
        raise AttestationError("cryptography (Ed25519) is unavailable; attestation fails closed")


def key_id_for(raw_public_key: bytes) -> str:
    if not isinstance(raw_public_key, bytes) or len(raw_public_key) != 32:
        raise AttestationError("Ed25519 public key must be 32 raw bytes")
    return "ed25519:" + hashlib.sha256(raw_public_key).hexdigest()[:32]


def _signed_message(claims: Mapping[str, object]) -> bytes:
    return _DOMAIN + canonical_json(dict(claims)).encode("utf-8")


def _claims(contract: dict, permit: dict, key_id: str) -> dict:
    verify_permit(contract, permit)
    return {
        "attestation_type": ATTESTATION_TYPE,
        "version": ATTESTATION_VERSION,
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "contract_id": permit["contract_id"],
        "permit_id": permit["permit_id"],
        "issuer": permit["issuer"],
    }


class AuthoritySigner:
    """Private-key holder. Construct only inside the authority-signer process."""

    __slots__ = ("_private_key", "key_id")

    def __init__(self, private_key):
        _require_crypto()
        if not isinstance(private_key, Ed25519PrivateKey):
            raise AttestationError("authority signer requires an Ed25519 private key")
        self._private_key = private_key
        raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = key_id_for(raw)

    def __repr__(self) -> str:  # never expose key material
        return f"AuthoritySigner(key_id={self.key_id!r})"

    @classmethod
    def from_key_file(cls, path: str) -> "AuthoritySigner":
        _require_crypto()
        if not path:
            raise AttestationError(f"{SIGNING_KEY_FILE_ENV} is not configured")
        try:
            st = os.stat(path)
        except OSError as exc:
            raise AttestationError("authority signing key file is unreadable") from exc
        if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise AttestationError("authority signing key file must not be group/world accessible (chmod 600)")
        try:
            with open(path, "rb") as fh:
                key = serialization.load_pem_private_key(fh.read(), password=None)
        except Exception as exc:  # do not chain parser details that could echo key bytes
            raise AttestationError("authority signing key file is not a valid PEM private key") from None
        return cls(key)

    @classmethod
    def from_env(cls) -> "AuthoritySigner":
        return cls.from_key_file(os.environ.get(SIGNING_KEY_FILE_ENV, ""))

    def public_key_hex(self) -> str:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def sign(self, contract: dict, permit: dict) -> dict:
        claims = _claims(contract, permit, self.key_id)
        signature = self._private_key.sign(_signed_message(claims)).hex()
        return {**claims, "signature": signature}


class AuthorityVerifier:
    """Public-key-only verifier. Holds no signing capability."""

    def __init__(self, keys: Mapping[str, Mapping[str, str]]):
        _require_crypto()
        if not isinstance(keys, Mapping) or not keys:
            raise AttestationError("authority trusted keyring is empty")
        self._active: dict[str, object] = {}
        self._revoked: set[str] = set()
        for key_id, entry in keys.items():
            if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
                raise AttestationError("authority trusted keyring contains a malformed key_id")
            if not isinstance(entry, Mapping) or set(entry) != {"public_key", "status"}:
                raise AttestationError(f"trusted key {key_id} entry is malformed")
            public_hex, status = entry["public_key"], entry["status"]
            if status not in _KEY_STATUSES:
                raise AttestationError(f"trusted key {key_id} has unknown status")
            if not isinstance(public_hex, str) or not _HEX64.fullmatch(public_hex):
                raise AttestationError(f"trusted key {key_id} public key is malformed")
            raw = bytes.fromhex(public_hex)
            if key_id_for(raw) != key_id:
                raise AttestationError(f"trusted key {key_id} does not match its public key")
            if status == "revoked":
                self._revoked.add(key_id)
            else:
                self._active[key_id] = Ed25519PublicKey.from_public_bytes(raw)

    @classmethod
    def from_json(cls, text: str) -> "AuthorityVerifier":
        try:
            spec = json.loads(text)
        except (TypeError, ValueError) as exc:
            raise AttestationError(f"{TRUSTED_KEYS_ENV} is not valid JSON") from exc
        if not isinstance(spec, Mapping) or set(spec) != {"version", "keys"} or spec["version"] != 1:
            raise AttestationError(f"{TRUSTED_KEYS_ENV} must be {{\"version\": 1, \"keys\": {{...}}}}")
        return cls(spec["keys"])

    @classmethod
    def from_env(cls) -> "AuthorityVerifier":
        text = os.environ.get(TRUSTED_KEYS_ENV)
        if not text:
            raise AttestationError(f"{TRUSTED_KEYS_ENV} is required to verify authority attestations")
        return cls.from_json(text)

    def verify(self, contract: dict, permit: dict, attestation: Mapping[str, object]) -> bool:
        if not isinstance(attestation, Mapping):
            raise AttestationError("attestation must be a mapping")
        if attestation.get("algorithm") == LEGACY_ALGORITHM or "version" not in attestation:
            raise AttestationError("legacy HMAC attestation rejected after Ed25519 cutover; "
                                   "re-issue it with the authority signer")
        if set(attestation) != _FIELDS:
            raise AttestationError("attestation schema mismatch")
        if attestation["attestation_type"] != ATTESTATION_TYPE:
            raise AttestationError("attestation type mismatch")
        if attestation["version"] != ATTESTATION_VERSION or isinstance(attestation["version"], bool):
            raise AttestationError("attestation version mismatch")
        if attestation["algorithm"] != ALGORITHM:
            raise AttestationError("attestation algorithm not allowed")
        key_id = attestation["key_id"]
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise AttestationError("attestation key_id is malformed")
        if key_id in self._revoked:
            raise AttestationError(f"attestation key {key_id} is revoked")
        public_key = self._active.get(key_id)
        if public_key is None:
            raise AttestationError(f"attestation key {key_id} is not trusted")
        signature = attestation["signature"]
        if not isinstance(signature, str) or not _HEX128.fullmatch(signature):
            raise AttestationError("attestation signature is malformed")
        claims = _claims(contract, permit, key_id)  # re-derived from authoritative records
        supplied = {k: v for k, v in attestation.items() if k != "signature"}
        if supplied != claims:
            raise AttestationError("attestation is not bound to permit")
        try:
            public_key.verify(bytes.fromhex(signature), _signed_message(claims))
        except InvalidSignature:
            raise AttestationError("attestation signature invalid") from None
        return True


def signing_material_present(environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return bool(env.get(SIGNING_KEY_FILE_ENV))


def issue_attestation(contract: dict, permit: dict, signer: AuthoritySigner) -> dict:
    if not isinstance(signer, AuthoritySigner):
        raise AttestationError("attestations can only be issued by an AuthoritySigner")
    return signer.sign(contract, permit)


def verify_attestation(contract: dict, permit: dict, attestation: dict,
                       verifier: AuthorityVerifier | None = None) -> bool:
    if verifier is None:
        verifier = AuthorityVerifier.from_env()
    if not isinstance(verifier, AuthorityVerifier):
        raise AttestationError("verification requires an AuthorityVerifier (HMAC secrets are not accepted)")
    return verifier.verify(contract, permit, attestation)


__all__ = ["ALGORITHM", "ATTESTATION_TYPE", "ATTESTATION_VERSION", "AttestationError", "AuthoritySigner",
           "AuthorityVerifier", "LEGACY_SECRET_ENV", "SIGNING_KEY_FILE_ENV", "TRUSTED_KEYS_ENV",
           "issue_attestation", "key_id_for", "signing_material_present", "verify_attestation"]
