"""Phase 2 security tests: Ed25519 authority signer / public-key verifier split."""
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import core.authority as authority
from core.attestation import (AttestationError, AuthoritySigner, AuthorityVerifier, SIGNING_KEY_FILE_ENV,
                              TRUSTED_KEYS_ENV)
from core.authority import authorize, load_attestation, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.mutation import TransitionError
from core.policy_registry import persist_policy
from tests.authority_keys import OTHER_SIGNING_KEY, keyring_json, signer

ROOT = Path(__file__).resolve().parents[1]


def _authority_dir(td, sign_with=None):
    reg = CapabilityRegistry()
    reg.register(Capability("cap", "1", "test", "research", status="ACTIVE"))
    reg.persist(td, "test")
    digest = persist_policy(td, {"policy_type": "GOVERNING_POLICY", "name": "ed25519-test"})
    contract = {"contract_type": "EXECUTION_CONTRACT", "task_id": "T", "scope": "research", "actor": "a",
                "capabilities": ["cap@1"], "input_digest": "sha256:in", "allowed_effects": ["persist_evidence"],
                "evidence_required": ["r"], "max_attempts": 1, "terminal_states": ["PASS", "BLOCKED"],
                "policy_digest": digest}
    stored = persist_contract(td, contract)
    permit = persist_permit(td, stored, "AIOS_AUTHORITY", signer=sign_with)
    return stored, permit


def _att_path(td, permit):
    return Path(td) / "authority" / "attestations" / (permit["permit_id"] + ".json")


def _rewrite(td, permit, **changes):
    path = _att_path(td, permit)
    att = json.loads(path.read_text())
    att.update(changes)
    path.write_text(json.dumps(att))


def _verifier(*entries):
    return AuthorityVerifier.from_json(keyring_json(*entries))


def test_valid_signature_verifies(tmp_path):
    c, p = _authority_dir(str(tmp_path))
    assert authorize(str(tmp_path), c["contract_id"], p["permit_id"])


def test_wrong_key_pair_rejected(tmp_path):
    c, p = _authority_dir(str(tmp_path), sign_with=AuthoritySigner(OTHER_SIGNING_KEY))
    with pytest.raises(TransitionError, match="not trusted"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])
    # Signature by other key relabelled with the trusted key_id fails cryptographically.
    _rewrite(str(tmp_path), p, key_id=signer().key_id)
    with pytest.raises(TransitionError, match="signature invalid"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


def test_modified_permit_rejected(tmp_path):
    c, p = _authority_dir(str(tmp_path))
    path = Path(tmp_path) / "authority" / "permits" / (p["permit_id"] + ".json")
    permit = json.loads(path.read_text())
    permit["max_attempts"] = 99
    path.write_text(json.dumps(permit))
    with pytest.raises((TransitionError, ValueError)):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


@pytest.mark.parametrize("field,value", [("contract_id", "CT-" + "0" * 64), ("permit_id", "PT-" + "0" * 64),
                                         ("issuer", "ATTACKER")])
def test_modified_binding_claims_rejected(tmp_path, field, value):
    c, p = _authority_dir(str(tmp_path))
    _rewrite(str(tmp_path), p, **{field: value})
    with pytest.raises(TransitionError, match="not bound to permit"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


def test_attestation_cannot_be_replayed_onto_other_contract(tmp_path):
    c, p = _authority_dir(str(tmp_path))
    att = load_attestation(str(tmp_path), p["permit_id"])
    other = dict(c, task_id="OTHER")
    other.pop("contract_id"); other.pop("record_type", None)
    from core.contract import issue_permit
    other_contract = persist_contract(str(tmp_path), other)
    other_permit = issue_permit({k: v for k, v in other_contract.items() if k not in ("contract_id", "record_type")},
                                "AIOS_AUTHORITY")
    v = _verifier((signer(), "active"))
    canonical = {k: v_ for k, v_ in other_contract.items() if k not in ("contract_id", "record_type")}
    with pytest.raises(AttestationError, match="not bound"):
        v.verify(canonical, other_permit, att)


def test_unknown_key_rejected(tmp_path):
    c, p = _authority_dir(str(tmp_path))
    _rewrite(str(tmp_path), p, key_id="ed25519:" + "f" * 32)
    with pytest.raises(TransitionError, match="not trusted"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


def test_revoked_key_rejected(tmp_path, monkeypatch):
    c, p = _authority_dir(str(tmp_path))
    monkeypatch.setenv(TRUSTED_KEYS_ENV, keyring_json((signer(), "revoked")))
    with pytest.raises(TransitionError, match="revoked"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


def test_rotation_reissue_under_new_key(tmp_path, monkeypatch):
    c, p = _authority_dir(str(tmp_path))
    new = AuthoritySigner(OTHER_SIGNING_KEY)
    monkeypatch.setenv(TRUSTED_KEYS_ENV, keyring_json((signer(), "revoked"), (new, "active")))
    with pytest.raises(TransitionError):
        authority.persist_attestation(str(tmp_path), c, p, new)  # no silent overwrite
    authority.persist_attestation(str(tmp_path), c, p, new, reissue=True)
    assert authorize(str(tmp_path), c["contract_id"], p["permit_id"])


@pytest.mark.parametrize("keys", [None, "", "not json", json.dumps({"version": 1, "keys": {}}),
                                  json.dumps({"version": 2, "keys": {}}),
                                  json.dumps({"version": 1, "keys": {"ed25519:" + "0" * 32:
                                              {"public_key": "00" * 32, "status": "active"}}}),
                                  json.dumps({"version": 1, "keys": {"rsa:1": {"public_key": "x", "status": "active"}}}),
                                  json.dumps({"version": 1, "keys": {signer().key_id:
                                              {"public_key": signer().public_key_hex(), "status": "maybe"}}})])
def test_missing_or_malformed_keyring_fails_closed(tmp_path, monkeypatch, keys):
    c, p = _authority_dir(str(tmp_path))
    if keys is None:
        monkeypatch.delenv(TRUSTED_KEYS_ENV)
    else:
        monkeypatch.setenv(TRUSTED_KEYS_ENV, keys)
    with pytest.raises(TransitionError, match="verifier unavailable"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


def test_missing_attestation_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(authority, "_process_signer", None)
    c, p = _authority_dir(str(tmp_path))
    with pytest.raises(TransitionError, match="missing"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


@pytest.mark.parametrize("sig", ["", "zz" * 64, "0" * 127, "0" * 128, 123])
def test_malformed_or_wrong_signature_rejected(tmp_path, sig):
    c, p = _authority_dir(str(tmp_path))
    _rewrite(str(tmp_path), p, signature=sig)
    with pytest.raises(TransitionError, match="signature"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


@pytest.mark.parametrize("algorithm", ["HMAC-SHA256", "none", "ed25519", "EdDSA", "RS256"])
def test_algorithm_downgrade_and_confusion_rejected(tmp_path, algorithm):
    c, p = _authority_dir(str(tmp_path))
    _rewrite(str(tmp_path), p, algorithm=algorithm)
    with pytest.raises(TransitionError, match="legacy HMAC|algorithm not allowed"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


@pytest.mark.parametrize("change", [{"version": 1}, {"version": True}, {"extra": "x"}])
def test_version_and_schema_tampering_rejected(tmp_path, change):
    c, p = _authority_dir(str(tmp_path))
    _rewrite(str(tmp_path), p, **change)
    with pytest.raises(TransitionError):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


def test_legacy_hmac_attestation_rejected_after_cutover(tmp_path, monkeypatch):
    monkeypatch.setattr(authority, "_process_signer", None)
    c, p = _authority_dir(str(tmp_path))
    secret = "legacy-shared-secret-32-characters"
    msg = f"{p['contract_id']}\n{p['permit_id']}\n{p['issuer']}".encode()
    legacy = {"attestation_type": "EXECUTION_PERMIT_ATTESTATION", "contract_id": p["contract_id"],
              "permit_id": p["permit_id"], "issuer": p["issuer"], "algorithm": "HMAC-SHA256",
              "signature": hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()}
    path = _att_path(str(tmp_path), p)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(legacy))
    monkeypatch.setenv("AIOS_AUTHORITY_ATTESTATION_SECRET", secret)  # even with the old secret present
    with pytest.raises(TransitionError, match="legacy HMAC attestation rejected"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])
    # Explicit migration by the signer replaces it; then it verifies.
    authority.persist_attestation(str(tmp_path), c, p, signer())
    assert authorize(str(tmp_path), c["contract_id"], p["permit_id"])


def test_verifying_process_refuses_signing_material(tmp_path, monkeypatch):
    c, p = _authority_dir(str(tmp_path))
    monkeypatch.setenv(SIGNING_KEY_FILE_ENV, str(tmp_path / "key.pem"))
    with pytest.raises(TransitionError, match="must not be configured in a verifying process"):
        authorize(str(tmp_path), c["contract_id"], p["permit_id"])


def test_verifier_has_no_signing_capability():
    v = _verifier((signer(), "active"))
    assert not any(hasattr(v, name) for name in ("sign", "_private_key", "issue"))
    with pytest.raises(AttestationError, match="AuthoritySigner"):
        authority.issue_attestation({}, {}, v)
    assert "PRIVATE" not in repr(signer()) and signer().key_id in repr(signer())


def _env(**extra):
    env = {k: v for k, v in os.environ.items()
           if k not in (SIGNING_KEY_FILE_ENV, TRUSTED_KEYS_ENV, "AIOS_AUTHORITY_ATTESTATION_SECRET")}
    env["PYTHONPATH"] = str(ROOT)
    env.update(extra)
    return env


def test_cross_process_sign_then_verify_and_runtime_cannot_sign(tmp_path, monkeypatch):
    monkeypatch.setattr(authority, "_process_signer", None)
    aios = tmp_path / "aios"; aios.mkdir()
    c, p = _authority_dir(str(aios))  # permit recorded unattested
    key_file = tmp_path / "authority-signing.pem"
    script = str(ROOT / "scripts" / "aios_authority_signer.py")
    gen = subprocess.run([sys.executable, script, "keygen", "--out", str(key_file)], env=_env(),
                         capture_output=True, text=True, check=True)
    entry = json.loads(gen.stdout)
    assert "PRIVATE" not in gen.stdout and "PRIVATE" not in gen.stderr
    trusted = json.dumps({"version": 1, "keys": entry})

    # Authority-signer process: has the key file, no trusted keyring.
    signed = subprocess.run([sys.executable, script, "sign", "--aios-dir", str(aios), "--permit-id", p["permit_id"]],
                            env=_env(**{SIGNING_KEY_FILE_ENV: str(key_file)}), capture_output=True, text=True)
    assert signed.returncode == 0, signed.stderr
    assert "PRIVATE" not in signed.stdout + signed.stderr

    # Execution-runtime process: public keys only. It verifies, and cannot sign.
    runtime = (
        "import sys, json\n"
        "from core.authority import authorize\n"
        "from core.attestation import AuthoritySigner, AttestationError\n"
        f"assert authorize({str(aios)!r}, {c['contract_id']!r}, {p['permit_id']!r})\n"
        "try:\n    AuthoritySigner.from_env()\nexcept AttestationError:\n    print('NO_SIGNING_CAPABILITY')\n"
    )
    out = subprocess.run([sys.executable, "-c", runtime], env=_env(**{TRUSTED_KEYS_ENV: trusted}),
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "NO_SIGNING_CAPABILITY" in out.stdout

    # A runtime process accidentally given the key file refuses to authorize.
    bad = subprocess.run([sys.executable, "-c", runtime],
                         env=_env(**{TRUSTED_KEYS_ENV: trusted, SIGNING_KEY_FILE_ENV: str(key_file)}),
                         capture_output=True, text=True)
    assert bad.returncode != 0 and "must not be configured in a verifying process" in bad.stderr


def test_signer_cli_fails_closed_without_key(tmp_path):
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "aios_authority_signer.py"), "sign",
                          "--aios-dir", str(tmp_path), "--permit-id", "PT-x"], env=_env(),
                         capture_output=True, text=True)
    assert out.returncode == 2 and "BLOCKED" in out.stderr


def test_migrate_reissues_legacy_attestations(tmp_path, monkeypatch):
    monkeypatch.setattr(authority, "_process_signer", None)
    aios = tmp_path / "aios"; aios.mkdir()
    c, p = _authority_dir(str(aios))
    path = _att_path(str(aios), p); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"algorithm": "HMAC-SHA256", "permit_id": p["permit_id"]}))
    key_file = tmp_path / "k.pem"
    script = str(ROOT / "scripts" / "aios_authority_signer.py")
    subprocess.run([sys.executable, script, "keygen", "--out", str(key_file)], env=_env(), check=True,
                   capture_output=True)
    out = subprocess.run([sys.executable, script, "migrate", "--aios-dir", str(aios)],
                         env=_env(**{SIGNING_KEY_FILE_ENV: str(key_file)}), capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["migrated"][0]["status"] == "REISSUED"
    assert json.loads(path.read_text())["algorithm"] == "Ed25519"
