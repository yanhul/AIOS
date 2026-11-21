import json
import pytest
from core.retry_ed25519 import RetryIssuerPublicKeyring, RetryIssuerTrustError, SIGNED_FIELDS, key_id_for, signing_bytes


class _TestSigner:
    def __init__(self, issuer, key):
        from cryptography.hazmat.primitives import serialization
        self.issuer = issuer
        self.key = key
        self.public_key = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.key_id = key_id_for(self.public_key)

    def sign(self, fields, *, now=1000):
        record = dict(fields, issuer=self.issuer, scope="effect.retry.approve", mode="EXPLICIT",
                      algorithm="Ed25519", issued_at=float(now), expires_at=float(now)+120,
                      key_id=self.key_id)
        record["signature"] = self.key.sign(signing_bytes(record)).hex()
        return record


def _record():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    signer = _TestSigner("issuer:independent", key)
    fields = {
        "record_type": "RETRY_AUTHORIZATION_ED25519", "authorization_id": "RA-" + "a" * 32,
        "effect_id": "EF-test", "contract_id": "CT-test", "permit_id": "PM-test",
        "actor": "agent:worker", "effect_state_digest": "b" * 64,
        "previous_attempt": 1, "previous_attempt_id": "EF-test:attempt:1",
        "attempt": 2, "attempt_id": "EF-test:attempt:2", "reason": "reviewed retry",
        "unknown_reason": "timeout", "provider": "provider:test",
        "state_attestation_digest": "d" * 64,
        "state_source_repository": "yanhul/AIOS-effect-state",
        "state_source_ref": "authority/effect-state", "state_source_commit": "a" * 40,
        "state_source_path": "effects/raw/EF-test.json", "state_attested_at": 999.0,
        "state_version": 1, "state_attestor": "aios-effect-state-authority",
        "state_attestor_key_id": "ed25519:" + "1" * 32,
        "state_attestation_commit": "b" * 40,
        "state_attestation_path": "effects/attested/EF-test.json",
    }
    return signer, signer.sign(fields)


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
    # Private signing helper exists only in this test module; production AIOS
    # verifier module intentionally exposes no signer class or private-key API.
    import core.retry_ed25519 as verifier
    assert not hasattr(verifier, "RetryAuthorizationSigner")
    assert not hasattr(verifier, "Ed25519PrivateKey")


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
        "state_attestation_digest": "d" * 64,
        "state_source_repository": "yanhul/AIOS-effect-state",
        "state_source_ref": "authority/effect-state", "state_source_commit": "a" * 40,
        "state_source_path": f"effects/raw/{current['effect_id']}.json", "state_attested_at": 1000.0,
        "state_version": 1, "state_attestor": "aios-effect-state-authority",
        "state_attestor_key_id": "ed25519:" + "1" * 32,
        "state_attestation_commit": "b" * 40,
        "state_attestation_path": f"effects/attested/{current['effect_id']}.json",
    }
    record = signer.sign(fields, now=1000)
    monkeypatch.setenv("AIOS_RETRY_ISSUER_ED25519_KEYRING", json.dumps({
        signer.issuer: {"key_id": signer.key_id, "public_key": signer.public_key}
    }))
    monkeypatch.setenv("AIOS_REQUIRE_EXECUTION_LINEAGE", "false")
    imported = import_retry_authorization(str(tmp_path), record, "agent-1", now=1001)
    assert imported["imported"]
    assert imported["retry_authorization"] == {"authorization_id": record["authorization_id"],
                                                  "mode": "EXPLICIT", "effect_id": effect["effect_id"], "attempt": 2}
    rel, verified = _verify_retry_authorization(
        str(tmp_path), record, current, "agent-1", 2,
        f"{effect['effect_id']}:attempt:2", None, 1001,
    )
    assert verified["algorithm"] == "Ed25519"
    assert rel.endswith(record["authorization_id"] + ".json")



def test_external_ed25519_authorization_import_then_single_use_retry_dispatch(tmp_path, monkeypatch):
    import json
    from core.effect_authority import (
        _effect_state_digest, _load_owned_effect, dispatch, import_retry_authorization,
        retry_dispatch, unknown, _load, _path, _verify_retry_authorization,
    )
    from core.mutation import TransitionError
    from tests.provider_keys import KEYRING, signed_not_applied_proof
    from tests.test_m6_effect_authority import _effect
    effect = _effect(tmp_path)
    first = f"{effect['effect_id']}:attempt:1"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", first, "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    current, _ = _load_owned_effect(str(tmp_path), effect["effect_id"], "agent-1", "test")
    signer, _ = _record()
    fields = {
        "record_type": "RETRY_AUTHORIZATION_ED25519", "authorization_id": "RA-" + "e" * 32,
        "effect_id": current["effect_id"], "contract_id": current["contract_id"],
        "permit_id": current["permit_id"], "actor": "agent-1",
        "effect_state_digest": _effect_state_digest(current), "previous_attempt": 1,
        "previous_attempt_id": first, "attempt": 2,
        "attempt_id": f"{effect['effect_id']}:attempt:2", "reason": "reviewed retry",
        "unknown_reason": current["unknown_reason"], "provider": "provider-1",
        "state_attestation_digest": "d" * 64,
        "state_source_repository": "yanhul/AIOS-effect-state",
        "state_source_ref": "authority/effect-state", "state_source_commit": "a" * 40,
        "state_source_path": f"effects/raw/{current['effect_id']}.json", "state_attested_at": 1000.0,
        "state_version": 1, "state_attestor": "aios-effect-state-authority",
        "state_attestor_key_id": "ed25519:" + "1" * 32,
        "state_attestation_commit": "b" * 40,
        "state_attestation_path": f"effects/attested/{current['effect_id']}.json",
    }
    record = signer.sign(fields, now=1000)
    monkeypatch.setenv("AIOS_RETRY_ISSUER_ED25519_KEYRING", json.dumps({
        signer.issuer: {"key_id": signer.key_id, "public_key": signer.public_key}
    }))
    monkeypatch.setenv("AIOS_REQUIRE_EXECUTION_LINEAGE", "false")
    imported = import_retry_authorization(str(tmp_path), record, "agent-1", now=1001)
    proof = signed_not_applied_proof(str(tmp_path), effect["effect_id"], "provider-1", now=1001)
    dispatched = retry_dispatch(
        str(tmp_path), effect["effect_id"], "agent-1", fields["attempt_id"], "provider-1", 2,
        retry_authorization=imported["retry_authorization"], not_applied_proof=proof,
        provider_keyring=KEYRING, now=1001,
    )
    assert dispatched["state"] == "DISPATCHED"
    assert dispatched["retry_authorization_id"] == record["authorization_id"]
    assert dispatched["consumed_retry_authorizations"] == [record["authorization_id"]]
    with pytest.raises(TransitionError, match="already consumed"):
        _verify_retry_authorization(
            str(tmp_path), imported["retry_authorization"], dispatched, "agent-1", 2,
            fields["attempt_id"], None, 1001,
        )


def test_production_ed25519_retry_with_lineage_not_applied_receipt_and_restart(tmp_path, monkeypatch):
    import json
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from core.authority import load_contract
    from core.effect_authority import (
        _effect_state_digest, _load, _path, _load_owned_effect, _verify_consumption_history,
        dispatch, import_retry_authorization, observe, retry_dispatch, unknown,
    )
    from core.execution_lineage import ExecutionLineage
    from tests.provider_keys import KEYRING, sign_observation, signed_not_applied_proof
    from tests.test_m6_effect_authority import _effect, _observation

    monkeypatch.setenv("AIOS_REQUIRE_EXECUTION_LINEAGE", "true")
    effect = _effect(tmp_path)
    contract = load_contract(str(tmp_path), effect["contract_id"])

    def lineage(attempt_id):
        fields = {
            "policy_revision": contract["policy_digest"],
            "environment_revision": "deployment:test:sha256:retry-ed25519",
            "capability_snapshot": {"capabilities": contract["capabilities"],
                                    "policy_digest": contract["policy_digest"]},
            "provider_revision": "1", "attempt_id": attempt_id,
            "trajectory_id": "trajectory:retry-ed25519-production-test",
        }
        fields["lineage_digest"] = ExecutionLineage(**fields).digest
        return fields

    first_attempt = f"{effect['effect_id']}:attempt:1"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", first_attempt, "provider-1",
             lineage=lineage(first_attempt))
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    current, _ = _load_owned_effect(str(tmp_path), effect["effect_id"], "agent-1", "test")

    private = Ed25519PrivateKey.generate()
    signer = _TestSigner("issuer:independent-production-test", private)
    auth_fields = {
        "record_type": "RETRY_AUTHORIZATION_ED25519", "authorization_id": "RA-" + "f" * 32,
        "effect_id": current["effect_id"], "contract_id": current["contract_id"],
        "permit_id": current["permit_id"], "actor": current["actor"],
        "effect_state_digest": _effect_state_digest(current),
        "previous_attempt": current["attempt"], "previous_attempt_id": current["attempt_id"],
        "attempt": 2, "attempt_id": f"{current['effect_id']}:attempt:2",
        "reason": "reviewed production retry", "unknown_reason": current["unknown_reason"],
        "provider": current["provider"],
        "state_attestation_digest": "d" * 64,
        "state_source_repository": "yanhul/AIOS-effect-state",
        "state_source_ref": "authority/effect-state",
        "state_source_commit": "a" * 40,
        "state_source_path": f"effects/raw/{current['effect_id']}.json",
        "state_attested_at": 1000.0, "state_version": 1,
        "state_attestor": "state-attestor:test", "state_attestor_key_id": "ed25519:" + "1" * 32,
        "state_attestation_commit": "b" * 40,
        "state_attestation_path": f"effects/attested/{current['effect_id']}.json",
    }
    record = signer.sign(auth_fields, now=1000)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    monkeypatch.setenv("AIOS_RETRY_ISSUER_ED25519_KEYRING", json.dumps({
        signer.issuer: {"key_id": signer.key_id, "public_key": public, "revoked": False}
    }))
    imported = import_retry_authorization(str(tmp_path), record, "agent-1", now=1001)
    proof = signed_not_applied_proof(str(tmp_path), effect["effect_id"], "provider-1", now=1002)
    dispatched = retry_dispatch(
        str(tmp_path), effect["effect_id"], "agent-1", auth_fields["attempt_id"], "provider-1", 2,
        imported["retry_authorization"], lineage=lineage(auth_fields["attempt_id"]),
        not_applied_proof=proof, provider_keyring=KEYRING, now=1002,
    )
    assert dispatched["state"] == "DISPATCHED"
    assert dispatched["retry_authorization_id"] == record["authorization_id"]
    assert record["authorization_id"] in dispatched["consumed_retry_authorizations"]

    observation = sign_observation(dispatched, _observation(effect["effect_id"], attempt=2), now=1003)
    observed = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS",
                       observation, provider_keyring=KEYRING, now=1003)
    assert observed["state"] == "OBSERVED_SUCCESS"
    receipt_id = observation["authentication"]["receipt_id"]
    receipt_path = tmp_path / "provider_receipts" / (receipt_id + ".json")
    assert receipt_path.is_file()

    # Restart boundary: reload only durable files and revalidate the one-use ledger.
    reloaded = _load(_path(str(tmp_path), effect["effect_id"]))
    _load_owned_effect(str(tmp_path), effect["effect_id"], "agent-1", "restart")
    _verify_consumption_history(str(tmp_path), reloaded)
    assert json.loads(receipt_path.read_text())["attempt_id"] == auth_fields["attempt_id"]
    assert reloaded["consumed_retry_authorizations"] == [record["authorization_id"]]