# AIOS-CONTRACT: A MiniMind effect reaches OBSERVED_* only with a receipt signed by the MiniMind
#                workload itself (provider key held outside the AIOS parent and the agent), bound
#                to effect/contract/permit/attempt/operation/outcome/raw-receipt digest. Only
#                PROMOTE is OBSERVED_SUCCESS; REJECT/INCONCLUSIVE/BLOCKED are OBSERVED_FAILURE.
# AIOS-REGRESSION: Audit F-04 — parent adapter signed an untrusted child result and mapped every
#                  terminal_state (incl. REJECT/BLOCKED) to OBSERVED_SUCCESS.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Forged/replayed/rebound/expired/tampered workload receipts, missing keys, schema.
# AIOS-BASELINE: Extends tests/test_audit_f04_provider_receipt.py.

import json
import os
import sys
from dataclasses import replace

import pytest

from adapters.minimind.runner import MiniMindAdapter, WITHHELD_ENV
from core import effect_authority as ea
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import PROVIDER_KEYRING_ENV, create_effect, dispatch
from core.policy_registry import persist_policy
from core.provider_authority import PROVIDER_SIGNING_KEYS_ENV, ProviderReceiptSigner, authenticate_receipt
from core.runtime import execute_attempt
from tests.provider_keys import SECRETS

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUB = os.path.join(REPO, "tests", "minimind_workload_stub.py")
ACTOR = "agent-1"
TASK = "mm-task"
KEY = SECRETS["minimind"]  # registered in the verifier keyring; held only by the workload stub
ARTIFACTS = {"workload_revision": "rev-1", "dataset_digest": "sha256:data", "tokenizer_digest": "sha256:tok",
             "model_digest": "sha256:model", "environment_digest": "sha256:env"}


def _receipt(terminal_state="PROMOTE", **over):
    evidence = {name: {**ARTIFACTS, "steps": 1} for name in ("training_receipt", "evaluation_receipt", "provenance")}
    evidence["evaluation_receipt"].update({"independent": True, "holdout": True})
    value = {"capability": "minimind.learning@1", "task_id": TASK, "terminal_state": terminal_state,
             "artifacts": dict(ARTIFACTS), "evidence": evidence}
    value.update(over)
    return value


def _setup(tmp_path, op="op-1"):
    aios = str(tmp_path)
    if not os.path.exists(os.path.join(aios, ".mm_contract.json")):
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
        with open(os.path.join(aios, ".mm_contract.json"), "w", encoding="utf-8") as fh:
            json.dump({"contract": contract, "permit_id": permit["permit_id"]}, fh)
    with open(os.path.join(aios, ".mm_contract.json"), encoding="utf-8") as fh:
        fx = json.load(fh)
    effect = create_effect(aios, contract_identity(fx["contract"]), op, ACTOR, fx["permit_id"], "external_effect")
    attempt = f"{effect['effect_id']}:attempt:1"
    dispatch(aios, effect["effect_id"], ACTOR, attempt, "minimind")
    return fx["contract"], ea._load(ea._path(aios, effect["effect_id"])), attempt


def _adapter(tmp_path, name="cfg", **cfg):
    cfg.setdefault("receipt", _receipt())
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return MiniMindAdapter(command=[sys.executable, "-I", STUB, REPO, str(path)])


def _run(tmp_path, adapter, op="op-1", **kw):
    contract, effect, attempt = _setup(tmp_path, op)
    result = execute_attempt(str(tmp_path), contract, effect, ACTOR, adapter, attempt, **kw)
    stored = ea._load(ea._path(str(tmp_path), effect["effect_id"]))
    assert stored["state"] == result["state"]
    return result, effect


def _assert_unknown(result, reason=None):
    assert result["state"] == "UNKNOWN", result
    assert "provider_observation" not in result
    if reason:
        assert reason in result["unknown_reason"], result["unknown_reason"]


# --- positive / outcome semantics ---------------------------------------------------------------

def test_workload_signed_promote_is_observed_success(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY))
    assert result["state"] == "OBSERVED_SUCCESS"
    po = result["provider_observation"]
    assert po["observation"]["minimind_receipt"]["terminal_state"] == "PROMOTE"
    assert po["provider_authentication"]["contract_id"] == result["contract_id"]
    assert KEY not in json.dumps(result)


@pytest.mark.parametrize("state", ["REJECT", "INCONCLUSIVE", "BLOCKED"])
def test_non_promote_terminal_states_are_never_task_success(tmp_path, state):
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY, receipt=_receipt(state)))
    assert result["state"] == "OBSERVED_FAILURE"
    assert result["provider_observation"]["observation"]["minimind_receipt"]["terminal_state"] == state


@pytest.mark.parametrize("state", ["REJECT", "INCONCLUSIVE", "BLOCKED"])
def test_workload_signed_success_for_non_promote_is_rejected(tmp_path, state):
    # Even a key-holding workload cannot label a non-PROMOTE result as success.
    adapter = _adapter(tmp_path, key=KEY, receipt=_receipt(state), outcome="OBSERVED_SUCCESS")
    result, _ = _run(tmp_path, adapter)
    _assert_unknown(result, "does not match terminal_state")


def test_promote_without_holdout_evidence_is_not_success(tmp_path):
    receipt = _receipt()
    receipt["evidence"]["evaluation_receipt"]["holdout"] = False
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY, receipt=receipt))
    _assert_unknown(result, "holdout")


# --- forged / unauthenticated -------------------------------------------------------------------

def test_child_fabricated_unsigned_receipt_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path))
    _assert_unknown(result, "not authenticated")


def test_child_signs_with_guessed_key_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, key="child-guessed-signing-key-0000"))
    _assert_unknown(result, "signature is invalid")


def test_child_impersonates_other_provider_key_stays_unknown(tmp_path):
    adapter = _adapter(tmp_path, key=SECRETS["provider-1"], sign_as="provider-1")
    result, _ = _run(tmp_path, adapter)
    _assert_unknown(result, "signature is invalid")


@pytest.mark.parametrize("auth", [
    "not-a-dict", {}, {"signature": "0" * 64},
])
def test_malformed_authentication_stays_unknown(tmp_path, auth):
    result, _ = _run(tmp_path, _adapter(tmp_path, authentication=auth))
    _assert_unknown(result, "non-authoritative provider observation")


def test_invalid_signature_value_stays_unknown(tmp_path):
    # Valid structure, signature replaced.
    good = tmp_path / "good.json"
    _run(tmp_path, _adapter(tmp_path, "a", key=KEY, save=str(good)))
    auth = json.loads(good.read_text())["authentication"]
    auth["signature"] = "f" * 64
    result, _ = _run(tmp_path, _adapter(tmp_path, "b", key=KEY, authentication=auth), op="op-2")
    _assert_unknown(result, "signature is invalid")


def test_child_declares_fake_artifact_digest_unsigned(tmp_path):
    fake = _receipt()
    fake["artifacts"]["model_digest"] = "sha256:forged"
    for ev in fake["evidence"].values():
        ev["model_digest"] = "sha256:forged"
    result, _ = _run(tmp_path, _adapter(tmp_path, receipt=fake))
    _assert_unknown(result, "not authenticated")


def test_artifact_digest_changed_after_workload_signed(tmp_path):
    fake = _receipt()
    fake["artifacts"]["model_digest"] = "sha256:forged"
    for ev in fake["evidence"].values():
        ev["model_digest"] = "sha256:forged"
    adapter = _adapter(tmp_path, key=KEY, receipt=fake, sign_receipt=_receipt())
    result, _ = _run(tmp_path, adapter)
    _assert_unknown(result, "signature is invalid")


class _TamperingParent(MiniMindAdapter):
    """Parent modifies the workload result after the workload signed it."""

    def execute(self, *, contract, effect, attempt_id):
        r = super().execute(contract=contract, effect=effect, attempt_id=attempt_id)
        obs = json.loads(json.dumps(r.observation))
        obs["minimind_receipt"]["evidence"]["evaluation_receipt"]["score"] = 0.99
        return replace(r, observation=obs)


def test_receipt_modified_after_signing_by_parent(tmp_path):
    base = _adapter(tmp_path, key=KEY)
    result, _ = _run(tmp_path, _TamperingParent(command=base.command))
    _assert_unknown(result, "signature is invalid")


class _SelfSigningParent(MiniMindAdapter):
    """Parent tries to sign an unsigned (REJECT) child result as success with a key it guessed."""

    def execute(self, *, contract, effect, attempt_id):
        r = super().execute(contract=contract, effect=effect, attempt_id=attempt_id)
        r = replace(r, outcome="OBSERVED_SUCCESS")
        return authenticate_receipt(r, effect, ProviderReceiptSigner("minimind", "parent-guessed-key-0000"))


def test_parent_cannot_sign_for_workload(tmp_path):
    base = _adapter(tmp_path, receipt=_receipt("REJECT"))
    result, _ = _run(tmp_path, _SelfSigningParent(command=base.command))
    _assert_unknown(result, "signature is invalid")


def test_adapter_has_no_signer_parameter():
    with pytest.raises(TypeError):
        MiniMindAdapter(command=["x"], signer=ProviderReceiptSigner("minimind", KEY))


# --- binding: task / capability / attempt / effect / contract / permit / operation ----------------

def test_wrong_task_id_signed_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY, receipt=_receipt(task_id="other-task")))
    _assert_unknown(result, "task binding")


def test_wrong_capability_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY, receipt=_receipt(capability="minimind.other@1")))
    _assert_unknown(result, "capability")


@pytest.mark.parametrize("field,cfg", [
    ("attempt", {"sign_attempt": "other:attempt:9"}),
    ("effect", {"sign_effect": {"effect_id": "EFFECT-other"}}),
    ("contract", {"sign_effect": {"contract_id": "sha256:other"}}),
    ("permit", {"sign_effect": {"permit_id": "PERMIT-other"}}),
    ("outcome", {"sign_outcome": "OBSERVED_FAILURE"}),
])
def test_signed_for_other_binding_stays_unknown(tmp_path, field, cfg):
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY, **cfg))
    _assert_unknown(result, "non-authoritative provider observation")


def test_wrong_operation_id_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY, operation_id="minimind:mm-task:other"))
    _assert_unknown(result, "provider_operation_id binding")


def test_replay_of_old_receipt_stays_unknown(tmp_path):
    saved = tmp_path / "old.json"
    first, _ = _run(tmp_path, _adapter(tmp_path, "a", key=KEY, save=str(saved)))
    assert first["state"] == "OBSERVED_SUCCESS"
    result, _ = _run(tmp_path, _adapter(tmp_path, "b", replay=str(saved)), op="op-2")
    _assert_unknown(result)


def test_replay_with_rebound_operation_still_fails_signature(tmp_path):
    saved = tmp_path / "old.json"
    _run(tmp_path, _adapter(tmp_path, "a", key=KEY, save=str(saved)))
    old_auth = json.loads(saved.read_text())["authentication"]
    result, _ = _run(tmp_path, _adapter(tmp_path, "b", authentication=old_auth), op="op-2")
    _assert_unknown(result, "not bound to this effect/attempt")  # old receipt bound to old effect/attempt


# --- keys / expiry ------------------------------------------------------------------------------

def test_missing_verifier_keyring_stays_unknown(tmp_path, monkeypatch):
    monkeypatch.delenv(PROVIDER_KEYRING_ENV)
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY))
    _assert_unknown(result, "keyring")


def test_parent_holding_workload_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(PROVIDER_SIGNING_KEYS_ENV, json.dumps({"minimind": KEY}))
    marker = tmp_path / "ran.json"
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY, env_report=str(marker)))
    _assert_unknown(result, "forgeable")
    assert not marker.exists()  # workload never started


def test_unparseable_parent_signing_env_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(PROVIDER_SIGNING_KEYS_ENV, "{not json")
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY))
    _assert_unknown(result, "forgeable")


def test_child_never_receives_aios_keys(tmp_path, monkeypatch):
    monkeypatch.setenv(PROVIDER_SIGNING_KEYS_ENV, json.dumps({"repo_patch": SECRETS["repo_patch"]}))
    report = tmp_path / "env.json"
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY, env_report=str(report)))
    assert result["state"] == "OBSERVED_SUCCESS"
    seen = set(json.loads(report.read_text()))
    assert os.environ.get(PROVIDER_KEYRING_ENV) and not (seen & WITHHELD_ENV)


def test_expired_receipt_stays_unknown(tmp_path):
    adapter = _adapter(tmp_path, key=KEY, now=1_000_000.0, ttl=60)
    result, _ = _run(tmp_path, adapter, now=1_000_000.0 + 3600)
    _assert_unknown(result, "expired")


def test_future_receipt_stays_unknown(tmp_path):
    adapter = _adapter(tmp_path, key=KEY, now=2_000_000.0, ttl=60)
    result, _ = _run(tmp_path, adapter, now=1_000_000.0)
    _assert_unknown(result, "future")


# --- incomplete / wrong schema -------------------------------------------------------------------

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
    result, _ = _run(tmp_path, _adapter(tmp_path, key=KEY, **cfg))
    _assert_unknown(result, reason)


def test_legacy_bare_receipt_stays_unknown(tmp_path):
    result, _ = _run(tmp_path, _adapter(tmp_path, raw_stdout=json.dumps(_receipt())))
    _assert_unknown(result, "envelope schema")
