# AIOS-CONTRACT: Provider evidence must be source-authenticated, not only content-hashed (PR #126 @18ec11f P1)
# AIOS-REGRESSION: A caller that builds an EvidenceRecord with a *valid* SHA-256 digest must not be able to
#                  (A) mark an effect OBSERVED_SUCCESS via observe(), or (B) record NOT_APPLIED and unlock a
#                  retry of a side effect that may already have happened. HMAC-sealed AIOS acceptance is not
#                  provider authenticity; legacy records are never upgraded; key revocation revokes trust.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: A process holding a trusted provider HMAC secret can still sign (use Ed25519 keys to keep
#                    the signing key out of AIOS entirely). Ed25519 path runs only when 'cryptography' exists.
# AIOS-BASELINE: 18ec11f (539 passed, 1 skipped)

import json
import os

import pytest

import core.runtime as runtime
from core.effect_authority import (
    dispatch, load_receipt, load_reconciliation, observe, reconcile_effect, receipt_source_authenticity,
    retry_dispatch,
)
from core.evaluation_plane import evaluate_persisted_receipt
from core.evidence import EvidenceRecord, verify_evidence
from core.mutation import TransitionError
from core.provider_trust import (
    AIOS_INVOKED_UNSIGNED, ED25519_ALG, LEGACY_UNVERIFIED, PROVIDER_SIGNED, TRUST_ENV, ProviderTrustError,
    attestation_payload, sign_attestation, trusted_keys, verify_attestation,
)
from core.record_seal import SEAL_ENV, seal
from core.runtime import ProviderReceipt, ReconciliationReport, execute
from tests.provider_trust_helpers import (
    KEY_ID, SECRET_ENV, TRUSTED_TEST_PROVIDERS, sign_observation, sign_reconciliation, signed_receipt,
)
from tests.test_m6_runtime import setup_authority
from tests.test_p0_receipt_lineage_crash_recovery import ACTOR, PROVIDER, Provider

ATTACKER_SECRET = "attacker-chosen-secret"


def _effect(aios, eid):
    return json.load(open(os.path.join(aios, "effects", eid + ".json")))


def _dispatched(tmp_path, max_attempts=2):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=max_attempts)
    from core.effect_authority import create_effect
    eff = create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    eid = eff["effect_id"]
    return aios, cid, pid, dispatch(aios, eid, ACTOR, f"{eid}:attempt:1", PROVIDER)


def _unknown(tmp_path, max_attempts=3):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=max_attempts)
    eff = execute(aios, cid, pid, "op-1", ACTOR, Provider("timeout"))
    assert eff["state"] == "UNKNOWN"
    return aios, eff


def _forged_evidence(eff, claim="provider executed operation"):
    """Exactly what an attacker can build: correct provider, attempt and a *valid* digest."""
    ev = EvidenceRecord("EV-forged", "OBSERVED", f"provider://{PROVIDER}/ops/x", claim,
                        eff["attempt_id"], PROVIDER).as_record()
    assert verify_evidence(ev)  # CONTENT_INTEGRITY holds -- that is the point
    return ev


def _obs(eff, ev, op="op-forged", **extra):
    return {"attempt_id": eff["attempt_id"], "provider": PROVIDER, "provider_operation_id": op,
            "effect_id": eff["effect_id"], "evidence": ev, **extra}


def _retry(aios, eff):
    eid = eff["effect_id"]
    return retry_dispatch(aios, eid, ACTOR, f"{eid}:attempt:2", PROVIDER, 2,
                          {"mode": "EXPLICIT", "effect_id": eid, "attempt": 2})


def _no_trust_for_fake_provider(monkeypatch):
    others = [p for p in TRUSTED_TEST_PROVIDERS if p != PROVIDER]
    monkeypatch.setenv(TRUST_ENV, json.dumps({"providers": {
        p: [{"key_id": KEY_ID, "algorithm": "HMAC-SHA256", "secret_env": SECRET_ENV,
                                "trust_boundary": "in-process"}] for p in others}}))


# ------------------------------------------------------------------ path A: forged OBSERVED_SUCCESS

def test_a_observe_rejects_valid_digest_evidence_without_provider_signature(tmp_path):
    aios, _, _, eff = _dispatched(tmp_path)
    with pytest.raises(ProviderTrustError, match="content integrity only"):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(eff, _forged_evidence(eff)))
    assert _effect(aios, eff["effect_id"])["state"] == "DISPATCHED"
    assert not os.path.isdir(os.path.join(aios, "receipts"))


def test_a_observe_rejects_even_when_provider_has_no_trusted_keys(tmp_path, monkeypatch):
    aios, _, _, eff = _dispatched(tmp_path)
    _no_trust_for_fake_provider(monkeypatch)
    with pytest.raises(ProviderTrustError):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(eff, _forged_evidence(eff)))
    assert _effect(aios, eff["effect_id"])["state"] == "DISPATCHED"


@pytest.mark.parametrize("attack", ["attacker_secret", "unknown_key_id", "wrong_algorithm", "extra_field", "garbage"])
def test_a_observe_rejects_attestation_not_from_a_trusted_key(tmp_path, attack):
    aios, _, _, eff = _dispatched(tmp_path)
    ev = _forged_evidence(eff)
    kw = dict(provider=PROVIDER, effect_id=eff["effect_id"], attempt_id=eff["attempt_id"],
              outcome="OBSERVED_SUCCESS", provider_operation_id="op-forged", evidence=ev)
    att = {
        "attacker_secret": lambda: sign_observation(**kw, secret=ATTACKER_SECRET),
        "unknown_key_id": lambda: sign_observation(**kw, secret=ATTACKER_SECRET, key_id="attacker-k"),
        "wrong_algorithm": lambda: {**sign_observation(**kw), "algorithm": ED25519_ALG},
        "extra_field": lambda: {**sign_observation(**kw), "payload": {"statement": "OBSERVED"}},
        "garbage": lambda: "signed-by-provider",
    }[attack]()
    with pytest.raises(ProviderTrustError):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(eff, ev, attestation=att))
    assert _effect(aios, eff["effect_id"])["state"] == "DISPATCHED"


@pytest.mark.parametrize("field,value", [
    ("outcome", "OBSERVED_FAILURE"), ("provider_operation_id", "op-other"),
    ("evidence", "other"), ("observation", {"status": "edited"}),
])
def test_a_genuine_signature_cannot_be_rebound_to_another_statement(tmp_path, field, value):
    aios, _, _, eff = _dispatched(tmp_path)
    ev = _forged_evidence(eff)
    obs = {"status": "ok"}
    att = sign_observation(provider=PROVIDER, effect_id=eff["effect_id"], attempt_id=eff["attempt_id"],
                           outcome="OBSERVED_SUCCESS", provider_operation_id="op-1", evidence=ev, observation=obs)
    outcome, submitted = "OBSERVED_SUCCESS", _obs(eff, ev, op="op-1", observation=obs, attestation=att)
    if field == "outcome":
        outcome = value
    elif field == "evidence":
        submitted["evidence"] = _forged_evidence(eff, claim="different claim")
    else:
        submitted[field] = value
    with pytest.raises(ProviderTrustError, match="does not match"):
        observe(aios, eff["effect_id"], ACTOR, outcome, submitted)


def test_a_signature_for_another_attempt_cannot_be_replayed(tmp_path):
    aios, _, _, eff = _dispatched(tmp_path)
    ev = _forged_evidence(eff)
    att = sign_observation(provider=PROVIDER, effect_id=eff["effect_id"], attempt_id=eff["effect_id"] + ":attempt:9",
                           outcome="OBSERVED_SUCCESS", provider_operation_id="op-1", evidence=ev)
    with pytest.raises(ProviderTrustError):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(eff, ev, op="op-1", attestation=att))


def test_a_signed_observation_is_accepted_and_marked_provider_signed(tmp_path):
    aios, _, _, eff = _dispatched(tmp_path)
    ev = _forged_evidence(eff)
    att = sign_observation(provider=PROVIDER, effect_id=eff["effect_id"], attempt_id=eff["attempt_id"],
                           outcome="OBSERVED_SUCCESS", provider_operation_id="op-1", evidence=ev)
    done = observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(eff, ev, op="op-1", attestation=att))
    receipt = load_receipt(aios, done["receipt_id"], require_provider_signed=True)
    assert receipt["source_authenticity"] == {"level": PROVIDER_SIGNED, "key_id": KEY_ID, "algorithm": "HMAC-SHA256",
                                              "trust_boundary": "in-process"}


def test_a_runtime_unsigned_receipt_for_trusted_provider_is_downgrade_and_becomes_unknown(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)

    class Unsigned(Provider):
        def _receipt(self, effect, attempt_id, op):
            return ProviderReceipt(self.name, effect["effect_id"], attempt_id, op, "OBSERVED_SUCCESS", {"status": "ok"})

    eff = execute(aios, cid, pid, "op-1", ACTOR, Unsigned())
    assert eff["state"] == "UNKNOWN" and "not authenticated" in eff["unknown_reason"]
    assert not os.path.isdir(os.path.join(aios, "receipts"))


def test_a_runtime_without_provider_keys_records_unsigned_and_never_upgrades(tmp_path, monkeypatch):
    aios = str(tmp_path)
    _no_trust_for_fake_provider(monkeypatch)
    _, cid, pid = setup_authority(tmp_path)

    class Unsigned(Provider):
        def _receipt(self, effect, attempt_id, op):
            return ProviderReceipt(self.name, effect["effect_id"], attempt_id, op, "OBSERVED_SUCCESS", {"status": "ok"})

    done = execute(aios, cid, pid, "op-1", ACTOR, Unsigned())
    assert done["state"] == "OBSERVED_SUCCESS"
    receipt = load_receipt(aios, done["receipt_id"])
    assert receipt_source_authenticity(receipt) == AIOS_INVOKED_UNSIGNED
    with pytest.raises(ProviderTrustError, match="provider signature required"):
        load_receipt(aios, done["receipt_id"], require_provider_signed=True)
    evaluate_persisted_receipt(aios, done["receipt_id"], evaluator_version="e1", rubric_version="r1",
                               verdict="PASS", result={"ok": True}, timestamp="t")
    (name,) = os.listdir(os.path.join(aios, "evaluations"))
    assert json.load(open(os.path.join(aios, "evaluations", name)))["source_authenticity"] == AIOS_INVOKED_UNSIGNED


def test_a_invoked_path_requires_the_execution_claim(tmp_path):
    aios, _, _, eff = _dispatched(tmp_path)
    receipt = signed_receipt(PROVIDER, eff["effect_id"], eff["attempt_id"], "op-1")
    with pytest.raises(TransitionError, match="execution claim"):
        runtime._observe_invoked(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS",
                                 runtime._provider_observation(receipt))


def test_a_editing_signed_observation_after_persistence_is_detected(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    assert receipt_source_authenticity(load_receipt(aios, done["receipt_id"])) == PROVIDER_SIGNED
    path = os.path.join(aios, "effects", done["effect_id"] + ".json")
    eff = json.load(open(path))
    eff["provider_observation"]["observation"]["status"] = "forged"
    json.dump(eff, open(path, "w"))
    with pytest.raises(ProviderTrustError):
        load_receipt(aios, done["receipt_id"])


def test_a_legacy_receipt_without_trust_fields_is_never_upgraded(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    from core.effect_authority import receipt_id_for
    from core.record_seal import unsealed_body
    rpath = os.path.join(aios, "receipts", done["receipt_id"] + ".json")
    body = unsealed_body(json.load(open(rpath)))
    for k in ("source_authenticity", "attestation", "receipt_id"):
        body.pop(k)
    rid = receipt_id_for(body)
    legacy = seal({**body, "receipt_id": rid})  # an AIOS-accepted pre-P1 receipt
    os.remove(rpath)
    json.dump(legacy, open(os.path.join(aios, "receipts", rid + ".json"), "w"))
    epath = os.path.join(aios, "effects", done["effect_id"] + ".json")
    eff = json.load(open(epath))
    eff["receipt_id"] = rid
    json.dump(eff, open(epath, "w"))
    assert receipt_source_authenticity(load_receipt(aios, rid)) == LEGACY_UNVERIFIED
    with pytest.raises(ProviderTrustError):
        load_receipt(aios, rid, require_provider_signed=True)


# ------------------------------------------------------------------ path B: forged NOT_APPLIED -> retry

def test_b_not_applied_with_valid_digest_but_no_signature_is_refused_and_retry_stays_blocked(tmp_path):
    aios, eff = _unknown(tmp_path)
    with pytest.raises(ProviderTrustError, match="content integrity only"):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", _forged_evidence(eff, "not applied"))
    assert load_reconciliation(aios, eff["effect_id"], 1) is None
    with pytest.raises(TransitionError, match="NOT_APPLIED"):
        _retry(aios, eff)
    assert _effect(aios, eff["effect_id"])["state"] == "UNKNOWN"


def test_b_not_applied_signed_with_attacker_key_is_refused(tmp_path):
    aios, eff = _unknown(tmp_path)
    ev = _forged_evidence(eff, "not applied")
    with pytest.raises(ProviderTrustError):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", ev,
                         attestation=sign_reconciliation(eff, "NOT_APPLIED", ev, secret=ATTACKER_SECRET))
    with pytest.raises(TransitionError):
        _retry(aios, eff)


def test_b_genuine_inconclusive_signature_cannot_be_replayed_as_not_applied(tmp_path):
    aios, eff = _unknown(tmp_path)
    ev = _forged_evidence(eff, "status unknown")
    att = sign_reconciliation(eff, "INCONCLUSIVE", ev)
    reconcile_effect(aios, eff["effect_id"], ACTOR, "INCONCLUSIVE", ev, attestation=att)
    with pytest.raises(ProviderTrustError, match="does not match"):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", ev, attestation=att)
    with pytest.raises(TransitionError):
        _retry(aios, eff)


def test_b_applied_reconciliation_requires_both_verdict_and_observation_signatures(tmp_path):
    aios, eff = _unknown(tmp_path)
    ev = _forged_evidence(eff, "applied")
    receipt = signed_receipt(PROVIDER, eff["effect_id"], eff["attempt_id"], "op-1")
    po = runtime._provider_observation(receipt)
    with pytest.raises(ProviderTrustError):  # no verdict signature
        reconcile_effect(aios, eff["effect_id"], ACTOR, "APPLIED", ev, outcome="OBSERVED_SUCCESS",
                         provider_observation=po)
    unsigned_po = {k: v for k, v in po.items() if k != "attestation"}
    with pytest.raises(ProviderTrustError):  # verdict signed, observation not
        reconcile_effect(aios, eff["effect_id"], ACTOR, "APPLIED", ev, outcome="OBSERVED_SUCCESS",
                         provider_observation=unsigned_po,
                         attestation=sign_reconciliation(eff, "APPLIED", ev, "OBSERVED_SUCCESS"))
    assert _effect(aios, eff["effect_id"])["state"] == "UNKNOWN"
    done = reconcile_effect(aios, eff["effect_id"], ACTOR, "APPLIED", ev, outcome="OBSERVED_SUCCESS",
                            provider_observation=po,
                            attestation=sign_reconciliation(eff, "APPLIED", ev, "OBSERVED_SUCCESS"))
    assert receipt_source_authenticity(load_receipt(aios, done["receipt_id"])) == PROVIDER_SIGNED


def test_b_legacy_sealed_not_applied_without_attestation_does_not_unlock_retry(tmp_path):
    aios, eff = _unknown(tmp_path)
    legacy = seal({"record_type": "EFFECT_RECONCILIATION", "effect_id": eff["effect_id"], "attempt": 1,
                   "attempt_id": eff["attempt_id"], "contract_id": eff["contract_id"], "provider": PROVIDER,
                   "verdict": "NOT_APPLIED", "evidence": _forged_evidence(eff, "not applied"), "actor": ACTOR,
                   "supersedes": None})  # AIOS_ACCEPTANCE only: genuine pre-P1 seal
    os.makedirs(os.path.join(aios, "reconciliations"), exist_ok=True)
    json.dump(legacy, open(os.path.join(aios, "reconciliations", f"{eff['effect_id']}-attempt-1.json"), "w"))
    with pytest.raises(ProviderTrustError, match="source authenticity"):
        _retry(aios, eff)
    assert _effect(aios, eff["effect_id"])["state"] == "UNKNOWN"


def test_b_revoking_provider_key_revokes_retry_authority(tmp_path, monkeypatch):
    aios, eff = _unknown(tmp_path)
    ev = _forged_evidence(eff, "not applied")
    reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", ev,
                     attestation=sign_reconciliation(eff, "NOT_APPLIED", ev))
    _no_trust_for_fake_provider(monkeypatch)
    with pytest.raises(ProviderTrustError, match="no trusted keys"):
        _retry(aios, eff)
    assert _effect(aios, eff["effect_id"])["state"] == "UNKNOWN"


def test_b_probe_with_forged_not_applied_is_not_recorded(tmp_path):
    aios, eff = _unknown(tmp_path)

    class ForgingProbe(Provider):
        def reconcile(self, *, effect, attempt_id):
            ev = _forged_evidence(effect, "not applied")
            return ReconciliationReport("NOT_APPLIED", ev, None,
                                        sign_reconciliation(effect, "NOT_APPLIED", ev, secret=ATTACKER_SECRET))

    out = runtime.reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, ForgingProbe())
    assert out["recorded"] is False and out["verdict"] == "INCONCLUSIVE"
    assert load_reconciliation(aios, eff["effect_id"], 1) is None
    with pytest.raises(TransitionError):
        _retry(aios, eff)


def test_b_genuine_signed_probe_unlocks_exactly_one_retry(tmp_path):
    aios, eff = _unknown(tmp_path)
    prov = Provider()  # never applied attempt 1 -> signed NOT_APPLIED
    rec = runtime.reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, prov)
    assert rec["verdict"] == "NOT_APPLIED" and rec["source_authenticity"]["level"] == PROVIDER_SIGNED
    assert _retry(aios, eff)["state"] == "DISPATCHED"


def test_reconcile_probe_is_not_triggered_for_non_owner(tmp_path):
    aios, eff = _unknown(tmp_path)

    class Counting(Provider):
        probes = 0

        def reconcile(self, *, effect, attempt_id):
            Counting.probes += 1
            return super().reconcile(effect=effect, attempt_id=attempt_id)

    with pytest.raises(PermissionError, match="effect owner"):
        runtime.reconcile_unknown_attempt(aios, eff["effect_id"], "agent:intruder", Counting())
    assert Counting.probes == 0


# ------------------------------------------------------------------ trust store hardening

def test_trust_store_inside_aios_state_is_refused(tmp_path, monkeypatch):
    aios = str(tmp_path)
    path = os.path.join(aios, "trust.json")
    json.dump({"providers": {PROVIDER: [{"key_id": "k", "algorithm": "HMAC-SHA256", "secret_env": SECRET_ENV,
                                "trust_boundary": "in-process"}]}},
              open(path, "w"))
    monkeypatch.setenv(TRUST_ENV, "@" + path)
    with pytest.raises(ProviderTrustError, match="inside AIOS state"):
        trusted_keys(PROVIDER, aios)


def test_trust_store_file_outside_state_is_loaded(tmp_path, monkeypatch):
    state, outside = tmp_path / "state", tmp_path / "etc"
    state.mkdir(); outside.mkdir()
    path = outside / "trust.json"
    path.write_text(json.dumps({"providers": {PROVIDER: [{"key_id": "k", "algorithm": "HMAC-SHA256",
                                                           "secret_env": SECRET_ENV,
                                "trust_boundary": "in-process"}]}}))
    monkeypatch.setenv(TRUST_ENV, "@" + str(path))
    assert set(trusted_keys(PROVIDER, str(state))) == {"k"}


@pytest.mark.parametrize("raw", ["not json", '{"providers": []}',
                                 '{"providers": {"fake-provider": [{"key_id": "k", "algorithm": "MD5"}]}}',
                                 '{"providers": {"fake-provider": [{"key_id": "k", "algorithm": "HMAC-SHA256", "trust_boundary": "in-process"},'
                                 ' {"key_id": "k", "algorithm": "HMAC-SHA256", "trust_boundary": "in-process"}]}}'])
def test_malformed_trust_store_fails_closed(monkeypatch, raw):
    monkeypatch.setenv(TRUST_ENV, raw)
    with pytest.raises(ProviderTrustError):
        trusted_keys(PROVIDER)


def test_provider_secret_equal_to_aios_seal_secret_is_refused(tmp_path, monkeypatch):
    aios, _, _, eff = _dispatched(tmp_path)
    monkeypatch.setenv(SECRET_ENV, os.environ[SEAL_ENV])
    ev = _forged_evidence(eff)
    att = sign_observation(provider=PROVIDER, effect_id=eff["effect_id"], attempt_id=eff["attempt_id"],
                           outcome="OBSERVED_SUCCESS", provider_operation_id="op-1", evidence=ev,
                           secret=os.environ[SEAL_ENV])
    with pytest.raises(ProviderTrustError, match="differ from the AIOS seal secret"):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(eff, ev, op="op-1", attestation=att))
