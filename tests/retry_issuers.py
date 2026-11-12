"""Test-only retry issuer trust anchor (deployment keyring) and signing helper."""
import json

from core.effect_authority import RETRY_APPROVE_SCOPE, RetryIssuerKeyring, issue_retry_authorization

ISSUER_SECRETS = {
    "operator:test": "test-operator-secret-0001",
    "operator:x": "test-operator-secret-000x",
}
KEYRING_SPEC = {name: {"secret": secret, "scopes": [RETRY_APPROVE_SCOPE]}
                for name, secret in ISSUER_SECRETS.items()}
KEYRING_SPEC["operator:readonly"] = {"secret": "readonly-operator-secret", "scopes": ["effect.read"]}
KEYRING_SPEC["operator:revoked"] = {"secret": "revoked-operator-secret", "scopes": [RETRY_APPROVE_SCOPE],
                                    "revoked": True}
KEYRING_JSON = json.dumps(KEYRING_SPEC)
KEYRING = RetryIssuerKeyring(KEYRING_SPEC)


def signed_retry_auth(aios_dir, effect_id, actor, attempt, issuer, reason, **kwargs):
    kwargs.setdefault("issuer_secret", ISSUER_SECRETS.get(issuer, "unregistered-issuer-secret"))
    kwargs.setdefault("keyring", KEYRING)
    return issue_retry_authorization(aios_dir, effect_id, actor, attempt, issuer, reason, **kwargs)
