import json
import pytest
from core.retry_ed25519 import RetryAuthorizationSigner, RetryIssuerPublicKeyring, RetryIssuerTrustError, SIGNED_FIELDS


def _record():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    signer = RetryAuthorizationSigner("issuer:independent", key, ttl_seconds=120)
    fields = {
        "record_type": "RETRY_AUTHORIZATION_ED25519", "authorization_id": "RA-" + "a" * 32,
        "effect_id": "EF-test", "contract_id": "CT-test", "permit_id": "PM-test",
        "actor": "agent:worker", "effect_state_digest": "b" * 64,
        "previous_attempt": 1, "previous_attempt_id": "EF-test:attempt:1",
        "attempt": 2, "attempt_id": "EF-test:attempt:2", "reason": "reviewed retry",
        "unknown_reason": "timeout", "provider": "provider:test",
    }
    return signer, signer.sign(fields, now=1000)


def test_ed25519_retry_sign_verify_and_tamper():
    signer, record = _record()
    ring = RetryIssuerPublicKeyring({signer.issuer: {"key_id": signer.key_id, "public_key": signer.public_key}})
    ring.verify(record)
    changed = dict(record, reason="different reason")
    with pytest.raises(RetryIssuerTrustError):
        ring.verify(changed)


def test_ed25519_retry_rejects_revoked_key():
    signer, record = _record()
    ring = RetryIssuerPublicKeyring({signer.issuer: {"key_id": signer.key_id, "public_key": signer.public_key, "revoked": True}})
    with pytest.raises(RetryIssuerTrustError, match="revoked"):
        ring.verify(record)


def test_ed25519_retry_signer_does_not_expose_private_key():
    signer, _ = _record()
    assert "private" not in repr(signer).lower()
    assert not hasattr(signer, "private_key")


def test_external_authorization_import_binds_current_unknown_effect(tmp_path, monkeypatch):
    import json
    from core.effect_authority import (
        _effect_state_digest, _load_owned_effect, dispatch, import_retry_authorization,
        unknown, _verify_retry_authorization,
    )
    from tests.test_m6_effect_authority import _effect
    effect = _effect(tmp_path)
    first = f"{effect['effect_id']}:attempt:1"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", first, "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    current, _ = _load_owned_effect(str(tmp_path), effect["effect_id"], "agent-1", "test")
    signer, _ = _record()
    fields = {
        "record_type": "RETRY_AUTHORIZATION_ED25519", "authorization_id": "RA-" + "c" * 32,
        "effect_id": current["effect_id"], "contract_id": current["contract_id"],
        "permit_id": current["permit_id"], "actor": "agent-1",
        "effect_state_digest": _effect_state_digest(current), "previous_attempt": 1,
        "previous_attempt_id": first, "attempt": 2,
        "attempt_id": f"{effect['effect_id']}:attempt:2", "reason": "reviewed retry",
        "unknown_reason": current["unknown_reason"], "provider": "provider-1",
    }
    record = signer.sign(fields, now=1000)
    monkeypatch.setenv("AIOS_RETRY_ISSUER_ED25519_KEYRING", json.dumps({
        signer.issuer: {"key_id": signer.key_id, "public_key": signer.public_key}
    }))
    monkeypatch.setenv("AIOS_REQUIRE_EXECUTION_LINEAGE", "false")
    assert import_retry_authorization(str(tmp_path), record, "agent-1", now=1001)["imported"]
    rel, verified = _verify_retry_authorization(
        str(tmp_path), record, current, "agent-1", 2,
        f"{effect['effect_id']}:attempt:2", None, 1001,
    )
    assert verified["algorithm"] == "Ed25519"
    assert rel.endswith(record["authorization_id"] + ".json")