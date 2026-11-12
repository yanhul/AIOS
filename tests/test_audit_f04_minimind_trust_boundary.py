# AIOS-CONTRACT: A MiniMind effect reaches OBSERVED_* only with a receipt signed by the MiniMind
#                workload's own Ed25519 private key and verified against the registered public key
#                and key id, bound to effect/contract/permit/attempt/provider/operation/outcome/
#                receipt digest/receipt id/validity window. MiniMind is Ed25519-only: no HMAC key
#                (incl. the whole AIOS_PROVIDER_KEYRING) can sign for it. Only PROMOTE is
#                OBSERVED_SUCCESS; REJECT/INCONCLUSIVE/BLOCKED are OBSERVED_FAILURE.
# AIOS-REGRESSION: Audit F-04 / F-04.1 — parent adapter signed untrusted child results; symmetric
#                  HMAC keyring holders could forge MiniMind receipts.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Forged/replayed/rebound/expired/tampered receipts, key/key-id impersonation,
#                    missing/malformed keys, HMAC downgrade, parent re-signing, schema.
# AIOS-BASELINE: Extends tests/test_audit_f04_provider_receipt.py.

import json
import os
import sys
from dataclasses import replace

import pytest

pytest.importorskip("cryptography")

from adapters.minimind.runner import UNISOLATED_FOR_TESTS, MiniMindAdapter, WITHHELD_ENV  # noqa: E402
from core import effect_authority as ea  # noqa: E402
from core import provider_ed25519 as ed  # noqa: E402
from core.authority import persist_contract, persist_permit  # noqa: E402
from core.capabilities import Capability, CapabilityRegistry  # noqa: E402
from core.contract import contract_identity  # noqa: E402
from core.effect_authority import PROVIDER_KEYRING_ENV, create_effect, dispatch  # noqa: E402
from core.policy_registry import persist_policy  # noqa: E402
from core.provider_authority import PROVIDER_SIGNING_KEYS_ENV, ProviderReceiptSigner, authenticate_receipt  # noqa: E402
from core.runtime import execute_attempt  # noqa: E402
from tests.provider_keys import (  # noqa: E402
    KEYRING_SPEC, SECRETS, ed25519_keyring_spec, ed25519_private_pem, ed25519_public_hex,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUB = os.path.join(REPO, "tests", "minimind_workload_stub.py")
ACTOR = "agent-1"
TASK = "mm-task"
ARTIFACTS = {"workload_revision": "rev-1", "dataset_digest": "sha256:data", "tokenizer_digest": "sha256:tok",
             "model_digest": "sha256:model", "environment_digest": "sha256:env"}


def _receipt(terminal_state="PROMOTE", **over):
    evidence = {name: {**ARTIFACTS, "steps": 1} for name in ("training_receipt", "evaluation_receipt", "provenance")}
    evidence["evaluation_receipt"].update({"independent": True, "holdout": True})
    value = {"capability": "minimind.learning@1", "task_id": TASK, "terminal_state": terminal_state,
             "artifacts": dict(ARTIFACTS), "evidence": evidence}
    value.update(over)
    return value


def _key_file(tmp_path, label="minimind-workload-test-key"):
    """The workload's own secret store (a 0600 PEM file); AIOS never reads it."""
    path = tmp_path / f"{label}.pem"
    if not path.exists():
        path.write_bytes(ed25519_private_pem(label))
        path.chmod(0o600)
    return str(path)


def _setup(tmp_path, op="op-1"):
    aios = str(tmp_path)
    fx_path = os.path.join(aios, ".mm_contract.json")
    if not os.path.exists(fx_path):
        registry = CapabilityRegistry()
        registry.register(Capability("minimind", "1", "test-fixture", "external_effect", status="ACTIVE"))
        registry.register(Capability("minimind.learning", "1", "test-fixture", "external_effect", status="ACTIVE"))
        registry.persist(aios, "test-fixture")
        policy = persist_policy(aios, {"policy_type": "GOVERNING_POLICY", "name": "minimind-f04"})
        contract = {
            "contract_type": "EXECUTION_CONTRACT", "task_id": TASK, "scope": "test", "actor": ACTOR,
            "capabilities": ["minimind@1", "minimind.learning@1"], "input_digest": "input",
            "allowed_effects": ["external_effect"], "evidence_required": ["provider_receipt"], "max_attempts": 2,
            "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE", "UNKNOWN"], "policy_digest": policy,
        }
        persist_contract(aios, contract)
        permit = persist_permit(aios, contract, ACTOR)
        with open(fx_path, "w", encoding="utf-8") as fh:
            json.dump({"contract": contract, "permit_id": permit["permit_id"]}, fh)
    with open(fx_path, encoding="utf-8") as fh:
        fx = json.load(fh)
    effect = create_effect(aios, contract_identity(fx["contract"]), op, ACTOR, fx["permit_id"], "external_effect")
    attempt = f"{effect['effect_id']}:attempt:1"
    dispatch(aios, effect["effect_id"], ACTOR, attempt, "minimind")
    return fx["contract"], ea._load(ea._path(aios, effect["effect_id"])), attempt


def _adapter(tmp_path, name="cfg", signed=True, **cfg):
    cfg.setdefault("receipt", _receipt())
    if signed and "key_file" not in cfg and "hmac_key" not in cfg:
        cfg["key_file"] = _key_file(tmp_path)
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return MiniMindAdapter(command=[sys.executable, "-I", STUB, REPO, str(path)], isolation=UNISOLATED_FOR_TESTS)


def _run(tmp_path, adapter, op="op-1", **kw):
    contract, effect, attempt = _setup(tmp_path, op)
    result = execute_attempt(str(tmp_path), contract, effect, ACTOR, adapter, attempt, **kw)
    path = ea._path(str(tmp_path), effect["effect_id"])
    stored = ea._load(path)
    assert stored["state"] == result["state"]  # returned state == persisted state
    with open(path, encoding="utf-8") as fh:
        assert "PRIVATE KEY" not in fh.read()  # private key never persisted
    return result, effect


def _assert_unknown(result, reason=None):
    assert result["state"] == "UNKNOWN", result
    assert "provider_observation" not in result
    if reason:
        assert reason in result["unknown_reason"], result["unknown_reason"]


def _saved_auth(tmp_path, name="seed"):
    saved = tmp_path / f"{name}.envelope.json"
    _run(tmp_path, _adapter(tmp_path, name, save=str(saved)), op=f"op-{name}")
    return json.loads(saved.read_text())


# --- 3 / 9: valid workload signature, outcome semantics ------------------------------------------

def test_workload_ed25519_signed_promote_is_observed_success(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path))
    assert result["state"] == "OBSERVED_SUCCESS"
    auth = result["provider_observation"]["provider_authentication"]
    assert auth["algorithm"] == "Ed25519" and auth["key_id"] == ed.key_id_for(ed25519_public_hex())
    assert result["provider_observation"]["observation"]["minimind_receipt"]["terminal_state"] == "PROMOTE"


@pytest.mark.parametrize("state", ["REJECT", "INCONCLUSIVE", "BLOCKED"])
def test_non_promote_terminal_states_are_never_task_success(tmp_path, state):
    result, _ = _run(tmp_path, _adapter(tmp_path, receipt=_receipt(state)))
    assert result["state"] == "OBSERVED_FAILURE"


@pytest.mark.parametrize("state", ["REJECT", "INCONCLUSIVE", "BLOCKED"])
def test_workload_signed_success_for_non_promote_is_rejected(tmp_path, state):
    result, _ = _run(tmp_path, _adapter(tmp_path, receipt=_receipt(state), outcome="OBSERVED_SUCCESS"))
    _assert_unknown(result, "does not match terminal_state")


def test_promote_without_holdout_evidence_is_not_success(tmp_path):
    receipt = _receipt()
    receipt["evidence"]["evaluation_receipt"]["holdout"] = False
    result, _ = _run(tmp_path, _adapter(tmp_path, receipt=receipt))
    _assert_unknown(result, "holdout")


# --- 1 / 2 / 10: parent trust domain cannot sign -----------------------------------------------

def test_hmac_keyring_cannot_sign_minimind_receipt_child_side(tmp_path):
    # Whoever holds AIOS_PROVIDER_KEYRING (it contains an HMAC "minimind" entry) still cannot sign.
    assert "minimind" in KEYRING_SPEC
    result, _ = _run(tmp_path, _adapter(tmp_path, hmac_key=KEYRING_SPEC["minimind"]["secret"]))
    _assert_unknown(result, "Ed25519 required")


class _HmacResigningParent(MiniMindAdapter):
    """Parent holding the full HMAC provider keyring re-signs the child result."""

    def execute(self, *, contract, effect, attempt_id):
        r = super().execute(contract=contract, effect=effect, attempt_id=attempt_id)
        secret = json.loads(os.environ[PROVIDER_KEYRING_ENV])["minimind"]["secret"]
        return authenticate_receipt(replace(r, outcome="OBSERVED_SUCCESS", authentication=None), effect,
                                    ProviderReceiptSigner("minimind", secret))


def test_parent_with_full_hmac_keyring_cannot_forge(tmp_path):
    base = _adapter(tmp_path, signed=False, receipt=_receipt("REJECT"))
    result, _ = _run(tmp_path, _HmacResigningParent(command=base.command, isolation=UNISOLATED_FOR_TESTS))
    _assert_unknown(result, "Ed25519 required")


class _PublicKeyOnlyParent(MiniMindAdapter):
    """Parent knows only the registered public key / key id and fabricates a signature."""

    def execute(self, *, contract, effect, attempt_id):
        r = super().execute(contract=contract, effect=effect, attempt_id=attempt_id)
        pub = ed25519_public_hex()
        auth = {"type": ed.ED25519_RECEIPT_TYPE, "algorithm": "Ed25519", "key_id": ed.key_id_for(pub),
                "receipt_id": "PR-" + "a" * 32, "contract_id": effect["contract_id"],
                "permit_id": effect["permit_id"], "issued_at": 1e12 - 10, "expires_at": 1e12 + 100,
                "signature": (pub * 2)}
        return replace(r, authentication=auth)


def test_parent_with_only_public_key_cannot_sign(tmp_path):
    base = _adapter(tmp_path, signed=False)
    result, _ = _run(tmp_path, _PublicKeyOnlyParent(command=base.command, isolation=UNISOLATED_FOR_TESTS), now=1e12)
    _assert_unknown(result, "Ed25519 signature is invalid")


def test_public_keyring_has_no_signing_capability(tmp_path):
    ring = ed.ProviderPublicKeyring(ed25519_keyring_spec())
    assert not any(hasattr(ring, name) for name in ("sign", "signer", "private_key"))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(ed25519_public_hex()))
    with pytest.raises(ValueError):
        ed.Ed25519ReceiptSigner("minimind", pub)
    signer = ed.Ed25519ReceiptSigner.from_pem_file("minimind", _key_file(tmp_path))
    assert "PRIVATE" not in repr(signer) and ed25519_private_pem().decode() not in repr(signer)


class _TamperingParent(MiniMindAdapter):
    def execute(self, *, contract, effect, attempt_id):
        r = super().execute(contract=contract, effect=effect, attempt_id=attempt_id)
        obs = json.loads(json.dumps(r.observation))
        obs["minimind_receipt"]["evidence"]["evaluation_receipt"]["score"] = 0.99
        return replace(r, observation=obs)


def test_parent_cannot_modify_authenticated_receipt(tmp_path):
    result, _ = _run(tmp_path, _TamperingParent(command=_adapter(tmp_path).command, isolation=UNISOLATED_FOR_TESTS))
    _assert_unknown(result, "Ed25519 signature is invalid")


class _OutcomeFlipParent(MiniMindAdapter):
    def execute(self, *, contract, effect, attempt_id):
        r = super().execute(contract=contract, effect=effect, attempt_id=attempt_id)
        return replace(r, outcome="OBSERVED_SUCCESS")


def test_parent_cannot_flip_outcome_of_signed_reject(tmp_path):
    result, _ = _run(tmp_path, _OutcomeFlipParent(command=_adapter(tmp_path, receipt=_receipt("REJECT")).command, isolation=UNISOLATED_FOR_TESTS))
    _assert_unknown(result, "Ed25519 signature is invalid")


def test_parent_cannot_substitute_another_signed_receipt(tmp_path):
    other = _saved_auth(tmp_path)  # valid workload receipt for a different effect
    result, _ = _run(tmp_path, _adapter(tmp_path, "b", signed=False, authentication=other["authentication"]),
                     op="op-2")
    _assert_unknown(result, "Ed25519 signature is invalid")


def test_adapter_has_no_signer_parameter():
    with pytest.raises(TypeError):
        MiniMindAdapter(command=["x"], signer=ProviderReceiptSigner("minimind", SECRETS["minimind"]))


def test_parent_holding_minimind_hmac_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(PROVIDER_SIGNING_KEYS_ENV, json.dumps({"minimind": SECRETS["minimind"]}))
    marker = tmp_path / "ran.json"
    result, _ = _run(tmp_path, _adapter(tmp_path, env_report=str(marker)))
    _assert_unknown(result, "forgeable")
    assert not marker.exists()


def test_child_never_receives_aios_keys(tmp_path):
    report = tmp_path / "env.json"
    result, _ = _run(tmp_path, _adapter(tmp_path, env_report=str(report)))
    assert result["state"] == "OBSERVED_SUCCESS"
    seen = set(json.loads(report.read_text()))
    assert os.environ.get(ed.ED25519_KEYRING_ENV) and not (seen & WITHHELD_ENV)


# --- 4 / 5: wrong keys, impersonation ------------------------------------------------------------

def test_wrong_private_key_rejected(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, key_file=_key_file(tmp_path, "attacker-key")))
    _assert_unknown(result, "key_id does not match")


def test_wrong_private_key_with_claimed_registered_key_id_rejected(tmp_path):
    adapter = _adapter(tmp_path, key_file=_key_file(tmp_path, "attacker-key"),
                       mutate_auth={"key_id": ed.key_id_for(ed25519_public_hex())})
    result, _ = _run(tmp_path, adapter)
    _assert_unknown(result, "Ed25519 signature is invalid")


def test_wrong_registered_public_key_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv(ed.ED25519_KEYRING_ENV, json.dumps(ed25519_keyring_spec("some-other-key")))
    result, _ = _run(tmp_path, _adapter(tmp_path))
    _assert_unknown(result, "key_id does not match")


def test_impersonating_other_registered_provider_key_rejected(tmp_path, monkeypatch):
    spec = {**ed25519_keyring_spec(), **ed25519_keyring_spec("other-provider-key", provider="provider-x")}
    monkeypatch.setenv(ed.ED25519_KEYRING_ENV, json.dumps(spec))
    adapter = _adapter(tmp_path, key_file=_key_file(tmp_path, "other-provider-key"), sign_as="provider-x")
    result, _ = _run(tmp_path, adapter)
    _assert_unknown(result, "key_id does not match")


def test_keyring_key_id_not_matching_public_key_fails_closed(tmp_path, monkeypatch):
    spec = ed25519_keyring_spec()
    spec["minimind"]["key_id"] = ed.key_id_for(ed25519_public_hex("other"))
    monkeypatch.setenv(ed.ED25519_KEYRING_ENV, json.dumps(spec))
    result, _ = _run(tmp_path, _adapter(tmp_path))
    _assert_unknown(result, "key_id for 'minimind' does not match its public key")


# --- 6: every signed binding changed after signing ----------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("contract_id", "CT-other"), ("permit_id", "PERMIT-other"), ("receipt_id", "PR-" + "b" * 32),
    ("issued_at", 1.0), ("expires_at", 9e12), ("signature", "0" * 128),
])
def test_auth_field_changed_after_signing_rejected(tmp_path, field, value):
    result, _ = _run(tmp_path, _adapter(tmp_path, mutate_auth={field: value}))
    _assert_unknown(result, "non-authoritative provider observation")


@pytest.mark.parametrize("cfg", [
    {"sign_attempt": "other:attempt:9"},
    {"sign_effect": {"effect_id": "EFFECT-other"}},
    {"sign_effect": {"contract_id": "CT-other"}},
    {"sign_effect": {"permit_id": "PERMIT-other"}},
    {"sign_outcome": "OBSERVED_FAILURE"},
    {"sign_operation_id": "minimind:mm-task:other"},
    {"sign_as": "provider-x"},
])
def test_signed_for_other_binding_rejected(tmp_path, cfg):
    result, _ = _run(tmp_path, _adapter(tmp_path, **cfg))
    _assert_unknown(result, "non-authoritative provider observation")


def test_receipt_digest_change_after_signing_rejected(tmp_path):
    fake = _receipt()
    fake["artifacts"]["model_digest"] = "sha256:forged"
    for ev in fake["evidence"].values():
        ev["model_digest"] = "sha256:forged"
    result, _ = _run(tmp_path, _adapter(tmp_path, receipt=fake, sign_receipt=_receipt()))
    _assert_unknown(result, "Ed25519 signature is invalid")


@pytest.mark.parametrize("mutate", ["task_id", "capability", "terminal_state", "evidence"])
def test_receipt_content_change_after_signing_rejected(tmp_path, mutate):
    changed = _receipt()
    if mutate == "task_id":
        changed["task_id"] = "other-task"
    elif mutate == "capability":
        changed["capability"] = "minimind.other@1"
    elif mutate == "terminal_state":
        changed["terminal_state"] = "REJECT"
    else:
        changed["evidence"]["training_receipt"]["steps"] = 999
    result, _ = _run(tmp_path, _adapter(tmp_path, receipt=changed, sign_receipt=_receipt(),
                                        outcome="OBSERVED_SUCCESS" if mutate != "terminal_state" else None))
    _assert_unknown(result)


def test_fake_artifact_digest_unsigned_stays_unknown(tmp_path):
    fake = _receipt()
    fake["artifacts"]["model_digest"] = "sha256:forged"
    for ev in fake["evidence"].values():
        ev["model_digest"] = "sha256:forged"
    result, _ = _run(tmp_path, _adapter(tmp_path, signed=False, receipt=fake))
    _assert_unknown(result, "not authenticated")


def test_wrong_task_id_signed_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, receipt=_receipt(task_id="other-task")))
    _assert_unknown(result, "task binding")


def test_wrong_capability_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, receipt=_receipt(capability="minimind.other@1")))
    _assert_unknown(result, "capability")


def test_wrong_operation_id_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, operation_id="minimind:mm-task:other"))
    _assert_unknown(result, "provider_operation_id binding")


# --- 7: replay / expiry / future -----------------------------------------------------------------

def test_replay_of_old_envelope_rejected(tmp_path):
    saved = tmp_path / "old.json"
    first, _ = _run(tmp_path, _adapter(tmp_path, "a", save=str(saved)))
    assert first["state"] == "OBSERVED_SUCCESS"
    result, _ = _run(tmp_path, _adapter(tmp_path, "b", replay=str(saved)), op="op-2")
    _assert_unknown(result)


def test_replay_after_terminal_rejected(tmp_path):
    from core.effect_authority import observe
    saved = tmp_path / "old.json"
    first, effect = _run(tmp_path, _adapter(tmp_path, "a", save=str(saved)))
    env = json.loads(saved.read_text())
    obs = {"provider": "minimind", "provider_operation_id": env["provider_operation_id"],
           "effect_id": effect["effect_id"], "attempt_id": first["attempt_id"],
           "observation": {"minimind_receipt": env["minimind_receipt"]}, "authentication": env["authentication"]}
    with pytest.raises(Exception):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", obs)
    assert ea._load(ea._path(str(tmp_path), effect["effect_id"]))["state"] == "OBSERVED_SUCCESS"


def test_expired_receipt_rejected(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, now=1_000_000.0, ttl=60), now=1_000_000.0 + 3600)
    _assert_unknown(result, "expired")


def test_future_receipt_rejected(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, now=2_000_000.0, ttl=60), now=1_000_000.0)
    _assert_unknown(result, "future")


# --- 8: missing / malformed key configuration fails closed ---------------------------------------

def test_missing_public_keyring_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv(ed.ED25519_KEYRING_ENV)
    result, _ = _run(tmp_path, _adapter(tmp_path))
    _assert_unknown(result, "Ed25519 public keyring")


def test_missing_public_keyring_no_hmac_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv(ed.ED25519_KEYRING_ENV)
    result, _ = _run(tmp_path, _adapter(tmp_path, hmac_key=KEYRING_SPEC["minimind"]["secret"]))
    _assert_unknown(result)


def test_provider_not_registered_in_public_keyring_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(ed.ED25519_KEYRING_ENV, json.dumps(ed25519_keyring_spec(provider="provider-x")))
    result, _ = _run(tmp_path, _adapter(tmp_path))
    _assert_unknown(result, "no Ed25519 public key registered")


@pytest.mark.parametrize("raw,reason", [
    ("{not json", "not valid JSON"),
    ("[]", "must be an object"),
    (json.dumps({"minimind": {"key_id": "x", "public_key": "zz"}}), "32 bytes hex"),
    (json.dumps({"minimind": {**ed25519_keyring_spec()["minimind"], "private_key": "00" * 32}}), "invalid fields"),
    (json.dumps({"minimind": {**ed25519_keyring_spec()["minimind"], "revoked": "no"}}), "boolean"),
])
def test_malformed_public_keyring_fails_closed(tmp_path, monkeypatch, raw, reason):
    monkeypatch.setenv(ed.ED25519_KEYRING_ENV, raw)
    result, _ = _run(tmp_path, _adapter(tmp_path))
    _assert_unknown(result, reason)


def test_revoked_public_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(ed.ED25519_KEYRING_ENV, json.dumps(ed25519_keyring_spec(revoked=True)))
    result, _ = _run(tmp_path, _adapter(tmp_path))
    _assert_unknown(result, "revoked")


def test_crypto_library_unavailable_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(ed, "ED25519_AVAILABLE", False)
    result, _ = _run(tmp_path, _adapter(tmp_path))
    _assert_unknown(result, "Ed25519 verification unavailable")


def test_unparseable_parent_signing_env_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(PROVIDER_SIGNING_KEYS_ENV, "{not json")
    result, _ = _run(tmp_path, _adapter(tmp_path))
    _assert_unknown(result, "forgeable")


# --- schema / legacy -----------------------------------------------------------------------------

@pytest.mark.parametrize("auth", ["not-a-dict", {}, {"signature": "0" * 128}])
def test_malformed_authentication_rejected(tmp_path, auth):
    result, _ = _run(tmp_path, _adapter(tmp_path, signed=False, authentication=auth))
    _assert_unknown(result, "non-authoritative provider observation")


@pytest.mark.parametrize("cfg,reason", [
    ({"raw_stdout": "not json"}, "not valid JSON"),
    ({"raw_stdout": "[]"}, "envelope schema"),
    ({"drop": ["outcome"]}, "envelope schema"),
    ({"drop": ["provider_operation_id"]}, "envelope schema"),
    ({"extra": {"evidence": {"level": "VERIFIED_DIGITAL"}}}, "envelope schema"),
    ({"outcome": "SUCCESS"}, "does not match terminal_state"),
    ({"receipt": {**_receipt(), "terminal_state": "DONE"}}, "terminal_state"),
    ({"receipt": {k: v for k, v in _receipt().items() if k != "evidence"}}, "schema mismatch"),
    ({"receipt": {**_receipt(), "artifacts": {"model_digest": "sha256:model"}}}, "artifact lineage"),
])
def test_incomplete_or_wrong_schema_stays_unknown(tmp_path, cfg, reason):
    result, _ = _run(tmp_path, _adapter(tmp_path, **cfg))
    _assert_unknown(result, reason)


def test_unsigned_envelope_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, signed=False))
    _assert_unknown(result, "not authenticated")


def test_legacy_bare_receipt_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, raw_stdout=json.dumps(_receipt())))
    _assert_unknown(result, "envelope schema")
