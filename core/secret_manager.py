"""ADC-backed Secret Manager access for verifier-only HMAC attestation secrets.

The caller supplies a Secret Manager client constructed with ADC. This module
accepts an explicit numeric secret version; aliases such as 'latest' are
rejected so every verification can be tied to an auditable version.
"""
from __future__ import annotations

import re
from typing import Any


_VERSION = re.compile(r"projects/[0-9A-Za-z-]+/secrets/[0-9A-Za-z_-]+/versions/[1-9][0-9]*")


class SecretMaterialUnavailable(RuntimeError):
    """Trusted secret material could not be read and verified."""


def read_hmac_attestation_secret(*, client: Any, version_resource: str) -> str:
    if not isinstance(version_resource, str) or not _VERSION.fullmatch(version_resource):
        raise SecretMaterialUnavailable("an explicit numeric Secret Manager version is required")
    try:
        response = client.access_secret_version(request={"name": version_resource})
        payload = response.payload.data
        if not isinstance(payload, bytes):
            raise SecretMaterialUnavailable("Secret Manager returned a non-byte payload")
        secret = payload.decode("utf-8")
    except SecretMaterialUnavailable:
        raise
    except Exception as exc:
        raise SecretMaterialUnavailable("Secret Manager access failed; authority resolution must DENY") from exc
    if len(secret) < 16:
        raise SecretMaterialUnavailable("attestation secret is missing or too short; DENY")
    return secret


__all__ = ["SecretMaterialUnavailable", "read_hmac_attestation_secret"]
