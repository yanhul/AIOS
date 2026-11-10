"""Provider source authenticity for external-effect evidence (PR #126 @18ec11f P1).

Three distinct properties, never conflated:

* ``CONTENT_INTEGRITY``   -- ``EvidenceRecord.digest`` (SHA-256). Anyone can
  recompute it; it proves only that the record was not altered *after* it was
  built.
* ``SOURCE_AUTHENTICITY`` -- a provider attestation verified here against a
  trust store configured *outside* AIOS state. Only this proves the provider
  issued the statement.
* ``AIOS_ACCEPTANCE``     -- the deployment HMAC seal (``record_seal``). It
  proves AIOS accepted/persisted the record, not that the provider issued it.

Trust store: ``AIOS_PROVIDER_TRUST`` holds either inline JSON or ``@/abs/path``::

    {"providers": {"<provider>": [
        {"key_id": "k1", "algorithm": "HMAC-SHA256", "secret_env": "PROVIDER_X_SECRET"},
        {"key_id": "k2", "algorithm": "Ed25519", "public_key": "<64 hex chars>"}
    ]}}

HMAC secrets are referenced by env var name, never embedded. Ed25519 needs the
optional ``cryptography`` package; without it Ed25519 keys fail closed. A trust
file located inside the AIOS state directory is refused (state writers must not
be able to grant themselves provider keys). Any configuration error fails
closed: no key => no SOURCE_AUTHENTICITY.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Mapping

from .mutation import TransitionError, canonical_json
from .record_seal import SEAL_ENV

TRUST_ENV = "AIOS_PROVIDER_TRUST"
DOMAIN = "aios-provider-attestation/v1"
HMAC_ALG = "HMAC-SHA256"
ED25519_ALG = "Ed25519"
ALGORITHMS = (HMAC_ALG, ED25519_ALG)

PROVIDER_SIGNED = "PROVIDER_SIGNED"
AIOS_INVOKED_UNSIGNED = "AIOS_INVOKED_UNSIGNED"
LEGACY_UNVERIFIED = "LEGACY_UNVERIFIED"
UNSIGNED = "UNSIGNED"

OBSERVED = "OBSERVED"
RECONCILED_PREFIX = "RECONCILED:"


class ProviderTrustError(TransitionError):
    """Provider attestation missing, malformed, untrusted or not matching."""


def _load_raw(aios_dir: str | None) -> dict:
    raw = os.environ.get(TRUST_ENV, "").strip()
    if not raw:
        return {}
    if raw.startswith("@"):
        path = os.path.realpath(raw[1:])
        if aios_dir is not None:
            state = os.path.realpath(aios_dir)
            if path == state or path.startswith(state + os.sep):
                raise ProviderTrustError("provider trust store must not live inside AIOS state")
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("providers", {}), dict):
        raise ProviderTrustError("provider trust store must be {'providers': {...}}")
    return data.get("providers", {})


def trusted_keys(provider: str, aios_dir: str | None = None) -> dict[str, dict]:
    """key_id -> key spec for ``provider``. Raises on a malformed store (fail closed)."""
    try:
        providers = _load_raw(aios_dir)
    except ProviderTrustError:
        raise
    except Exception as exc:  # noqa: BLE001 - unreadable/invalid store => fail closed
        raise ProviderTrustError(f"provider trust store is unreadable: {type(exc).__name__}: {exc}") from exc
    specs = providers.get(provider, [])
    if not isinstance(specs, list):
        raise ProviderTrustError(f"trust entry for {provider} must be a list")
    keys: dict[str, dict] = {}
    for spec in specs:
        if not isinstance(spec, dict):
            raise ProviderTrustError("provider key spec must be an object")
        key_id, alg = spec.get("key_id"), spec.get("algorithm")
        if not isinstance(key_id, str) or not key_id.strip() or key_id in keys:
            raise ProviderTrustError("provider key_id must be a unique non-empty string")
        if alg not in ALGORITHMS:
            raise ProviderTrustError(f"unsupported provider key algorithm: {alg}")
        keys[key_id] = spec
    return keys


def provider_has_trust(provider: str, aios_dir: str | None = None) -> bool:
    return bool(trusted_keys(provider, aios_dir))


def _hmac_secret(spec: Mapping[str, Any]) -> bytes:
    name = spec.get("secret_env")
    value = os.environ.get(name, "") if isinstance(name, str) and name else ""
    if not value:
        raise ProviderTrustError(f"provider HMAC secret env {name!r} is not configured")
    if value == os.environ.get(SEAL_ENV, object()):
        # The provider must not share the AIOS acceptance key: that would make
        # AIOS_ACCEPTANCE and SOURCE_AUTHENTICITY the same claim again.
        raise ProviderTrustError("provider secret must differ from the AIOS seal secret")
    return value.encode("utf-8")


def _message(payload: Mapping[str, Any]) -> bytes:
    return DOMAIN.encode("utf-8") + b"\n" + canonical_json(dict(payload)).encode("utf-8")


def attestation_payload(*, provider, effect_id, attempt_id, statement, evidence,
                        outcome=None, provider_operation_id=None, observation=None) -> dict:
    """The exact statement a provider signs. Built by AIOS from its own context."""
    if not isinstance(evidence, Mapping) or not isinstance(evidence.get("digest"), str):
        raise ProviderTrustError("attestation requires evidence with a digest")
    obs_digest = None
    if observation is not None:
        obs_digest = hashlib.sha256(canonical_json(observation).encode("utf-8")).hexdigest()
    return {"domain": DOMAIN, "provider": provider, "effect_id": effect_id, "attempt_id": attempt_id,
            "statement": statement, "outcome": outcome, "provider_operation_id": provider_operation_id,
            "evidence_digest": evidence["digest"], "observation_digest": obs_digest}


def sign_attestation(payload: Mapping[str, Any], *, key_id: str, algorithm: str = HMAC_ALG,
                     secret: bytes | str | None = None, private_key: Any = None) -> dict:
    """Provider-side helper (adapters/tests). AIOS itself never calls this."""
    msg = _message(payload)
    if algorithm == HMAC_ALG:
        if not secret:
            raise ProviderTrustError("HMAC attestation requires a secret")
        key = secret.encode("utf-8") if isinstance(secret, str) else secret
        sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
    elif algorithm == ED25519_ALG:
        if private_key is None:
            raise ProviderTrustError("Ed25519 attestation requires a private key")
        sig = private_key.sign(msg).hex()
    else:
        raise ProviderTrustError(f"unsupported provider key algorithm: {algorithm}")
    return {"key_id": key_id, "algorithm": algorithm, "signature": sig}


def _verify_ed25519(spec, msg, sig_hex) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ProviderTrustError("Ed25519 provider keys require the 'cryptography' package") from exc
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(spec.get("public_key", "")))
        pub.verify(bytes.fromhex(sig_hex), msg)
        return True
    except Exception:  # noqa: BLE001 - any parse/verify failure is a rejection
        return False


def verify_attestation(attestation: Any, payload: Mapping[str, Any], aios_dir: str | None = None) -> dict:
    """Verify ``attestation`` over the AIOS-built ``payload``; return the trust stamp.

    Raises ProviderTrustError unless a key trusted for ``payload['provider']``
    produced the signature over exactly this payload.
    """
    if not isinstance(attestation, Mapping):
        raise ProviderTrustError("provider attestation is missing")
    if set(attestation) - {"key_id", "algorithm", "signature"}:
        raise ProviderTrustError("provider attestation has unexpected fields")
    provider = payload.get("provider")
    keys = trusted_keys(provider, aios_dir)
    if not keys:
        raise ProviderTrustError(f"no trusted keys configured for provider {provider!r}")
    spec = keys.get(attestation.get("key_id"))
    if spec is None:
        raise ProviderTrustError("provider attestation key is not trusted for this provider")
    alg, sig = attestation.get("algorithm"), attestation.get("signature")
    if alg != spec["algorithm"] or not isinstance(sig, str) or not sig:
        raise ProviderTrustError("provider attestation algorithm/signature mismatch")
    msg = _message(payload)
    if alg == HMAC_ALG:
        ok = hmac.compare_digest(sig, hmac.new(_hmac_secret(spec), msg, hashlib.sha256).hexdigest())
    else:
        ok = _verify_ed25519(spec, msg, sig)
    if not ok:
        raise ProviderTrustError("provider attestation signature does not match the statement")
    return {"level": PROVIDER_SIGNED, "key_id": attestation["key_id"], "algorithm": alg}


__all__ = [
    "TRUST_ENV", "DOMAIN", "HMAC_ALG", "ED25519_ALG", "PROVIDER_SIGNED", "AIOS_INVOKED_UNSIGNED",
    "LEGACY_UNVERIFIED", "UNSIGNED", "OBSERVED", "RECONCILED_PREFIX", "ProviderTrustError",
    "attestation_payload", "sign_attestation", "verify_attestation", "trusted_keys", "provider_has_trust",
]
