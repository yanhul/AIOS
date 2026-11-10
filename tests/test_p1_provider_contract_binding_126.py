# AIOS-CONTRACT: Persisted provider identity is re-bound to the contract on every load; provider trust
#                boundaries are explicit (PR #126 re-review @218070b)
# AIOS-REGRESSION: (1) swapping the provider in effect JSON on disk for a provider that holds a *valid*
#                  trusted signing key but is not a contract capability must be refused before any probe,
#                  with no receipt and no state change; (2) HMAC keys need an explicit in-process trust
#                  boundary and can be disabled; (3) Ed25519 (independent boundary) is exercised for real,
#                  never skipped in CI (AIOS_REQUIRE_CRYPTO_TESTS=1).
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Ed25519 private keys live in-test; real provider key custody is out of AIOS scope.
# AIOS-BASELINE: 218070b (574 passed, 1 skipped)

import json
import os

import pytest

import core.runtime as runtime
from core.effect_authority import (
    load_receipt, load_reconciliation, observe, reconcile_effect, receipt_source_authenticity,
    retry_dispatch,
)
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.provider_trust import (
    ASYMMETRIC_ONLY_ENV, ED25519_ALG, INDEPENDENT, OBSERVED, PROVIDER_SIGNED, RECONCILED_PREFIX, TRUST_ENV,
    ProviderTrustError, attestation_payload, sign_attestation, trusted_keys, verify_attestation,
)
from core.runtime import ProviderReceipt, ReconciliationReport, execute
from tests.provider_trust_helpers import sign_observation, sign_reconciliation, signed_receipt
from tests.test_m6_runtime import setup_authority
from tests.test_p0_receipt_lineage_crash_recovery import ACTOR, PROVIDER, Provider

OUTSIDER = "provider-a"  # holds a trusted test key (conftest) but is NOT in the contract (fake-provider@1)


def _effect_path(aios, eid):
    return os.path.join(aios, "effects", eid + ".json")


def _unknown(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    eff = execute(aios, cid, pid, "op-1", ACTOR, Provider("timeout"))
    assert eff["state"] == "UNKNOWN"
    return aios, eff


def _swap_provider_on_disk(aios, eid, provider=OUTSIDER, **extra):
    path = _effect_path(aios, eid)
    eff = json.load(open(path))
    eff.update(provider=provider, **extra)
    json.dump(eff, open(path, "w"))
    return eff, open(path, "rb").read()


def _ev(eff, claim):
    return EvidenceRecord(f"EV-{claim}", "OBSERVED", f"provider://{eff['provider']}/status", claim,
                          eff["attempt_id"], eff["provider"]).as_record()


class OutsiderProbe(Provider):
    name = OUTSIDER
    probes = 0

    def reconcile(self, *, effect, attempt_id):
        OutsiderProbe.probes += 1
        ev = _ev(effect, "applied")
        receipt = signed_receipt(self.name, effect["effect_id"], attempt_id, "op-x")
        return ReconciliationReport("APPLIED", ev, receipt,
                                    sign_reconciliation(effect, "APPLIED", ev, "OBSERVED_SUCCESS"))


# ------------------------------------------------------------------ P1: provider <-> contract binding

def test_swapped_outsider_provider_with_valid_key_is_refused_before_probe(tmp_path):
    aios, eff = _unknown(tmp_path)
    assert trusted_keys(OUTSIDER)  # the outsider really does hold a trusted key
    _, before = _swap_provider_on_disk(aios, eff["effect_id"])
    OutsiderProbe.probes = 0
    with pytest.raises(TransitionError, match="not an authorized contract capability"):
        runtime.reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, OutsiderProbe())
    assert OutsiderProbe.probes == 0
    assert not os.path.isdir(os.path.join(aios, "receipts"))
    assert load_reconciliation(aios, eff["effect_id"], 1) is None
    assert open(_effect_path(aios, eff["effect_id"]), "rb").read() == before  # state untouched


def test_swapped_outsider_provider_cannot_commit_signed_applied_directly(tmp_path):
    aios, eff = _unknown(tmp_path)
    swapped, before = _swap_provider_on_disk(aios, eff["effect_id"])
    ev = _ev(swapped, "applied")
    po = runtime._provider_observation(signed_receipt(OUTSIDER, eff["effect_id"], eff["attempt_id"], "op-x"))
    with pytest.raises(TransitionError, match="not an authorized contract capability"):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "APPLIED", ev, outcome="OBSERVED_SUCCESS",
                         provider_observation=po,
                         attestation=sign_reconciliation(swapped, "APPLIED", ev, "OBSERVED_SUCCESS"))
    with pytest.raises(TransitionError, match="not an authorized contract capability"):
        reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", _ev(swapped, "na"),
                         attestation=sign_reconciliation(swapped, "NOT_APPLIED", _ev(swapped, "na")))
    assert not os.path.isdir(os.path.join(aios, "receipts"))
    assert open(_effect_path(aios, eff["effect_id"]), "rb").read() == before


def test_swapped_outsider_provider_cannot_observe_dispatched_attempt(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    from core.effect_authority import create_effect, dispatch
    eff = create_effect(aios, cid, "op-1", ACTOR, pid, "external_effect")
    eff = dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:1", PROVIDER)
    swapped, before = _swap_provider_on_disk(aios, eff["effect_id"])
    ev = _ev(swapped, "done")
    att = sign_observation(provider=OUTSIDER, effect_id=eff["effect_id"], attempt_id=eff["attempt_id"],
                           outcome="OBSERVED_SUCCESS", provider_operation_id="op-x", evidence=ev)
    with pytest.raises(TransitionError, match="not an authorized contract capability"):
        observe(aios, eff["effect_id"], ACTOR, "OBSERVED_SUCCESS",
                {"attempt_id": eff["attempt_id"], "provider": OUTSIDER, "provider_operation_id": "op-x",
                 "evidence": ev, "attestation": att})
    assert open(_effect_path(aios, eff["effect_id"]), "rb").read() == before


def test_swapped_provider_cannot_be_retried(tmp_path):
    aios, eff = _unknown(tmp_path)
    _swap_provider_on_disk(aios, eff["effect_id"])
    with pytest.raises(TransitionError, match="not an authorized contract capability"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", OUTSIDER, 2,
                       {"mode": "EXPLICIT", "effect_id": eff["effect_id"], "attempt": 2})


@pytest.mark.parametrize("edit", [{"attempt_id": "EF-other:attempt:1"}, {"provider": ""}, {"attempt": 0}])
def test_tampered_persisted_attempt_identity_is_refused(tmp_path, edit):
    aios, eff = _unknown(tmp_path)
    _swap_provider_on_disk(aios, eff["effect_id"], provider=edit.get("provider", PROVIDER),
                           **{k: v for k, v in edit.items() if k != "provider"})
    with pytest.raises(TransitionError):
        runtime.reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, Provider())


# ------------------------------------------------------------------ HMAC trust boundary policy

def _hmac_store(**spec):
    return json.dumps({"providers": {PROVIDER: [{"key_id": "k", "algorithm": "HMAC-SHA256",
                                                 "secret_env": "AIOS_TEST_FAKE_PROVIDER_SECRET", **spec}]}})


def test_hmac_key_without_explicit_in_process_boundary_is_refused(monkeypatch):
    monkeypatch.setenv(TRUST_ENV, _hmac_store())
    with pytest.raises(ProviderTrustError, match="in-process"):
        trusted_keys(PROVIDER)
    monkeypatch.setenv(TRUST_ENV, _hmac_store(trust_boundary="independent"))
    with pytest.raises(ProviderTrustError, match="in-process"):
        trusted_keys(PROVIDER)


def test_asymmetric_only_policy_disables_hmac_keys_and_blocks_hmac_signed_retry(tmp_path, monkeypatch):
    aios, eff = _unknown(tmp_path)
    ev = _ev(eff, "na")
    reconcile_effect(aios, eff["effect_id"], ACTOR, "NOT_APPLIED", ev,
                     attestation=sign_reconciliation(eff, "NOT_APPLIED", ev))
    monkeypatch.setenv(ASYMMETRIC_ONLY_ENV, "1")
    with pytest.raises(ProviderTrustError, match="asymmetric-only"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", PROVIDER, 2,
                       {"mode": "EXPLICIT", "effect_id": eff["effect_id"], "attempt": 2})


def test_hmac_stamp_records_in_process_boundary(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    assert load_receipt(aios, done["receipt_id"])["source_authenticity"]["trust_boundary"] == "in-process"


# ------------------------------------------------------------------ Ed25519: independent boundary, mandatory in CI

@pytest.fixture
def ed():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        if os.environ.get("AIOS_REQUIRE_CRYPTO_TESTS") == "1":
            pytest.fail("AIOS_REQUIRE_CRYPTO_TESTS=1 but 'cryptography' is not installed")
        pytest.skip("cryptography not installed (CI sets AIOS_REQUIRE_CRYPTO_TESTS=1 and never skips)")

    def new():
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        return key, pub
    return new


def _ed_store(monkeypatch, *keys):
    monkeypatch.setenv(ASYMMETRIC_ONLY_ENV, "1")  # Ed25519 must work with HMAC fully disabled
    monkeypatch.setenv(TRUST_ENV, json.dumps({"providers": {PROVIDER: [
        {"key_id": kid, "algorithm": ED25519_ALG, "public_key": pub} for kid, pub in keys]}}))


class EdProvider(Provider):
    """Provider that holds an Ed25519 private key AIOS never sees."""

    def __init__(self, key, key_id, mode="ok"):
        super().__init__(mode)
        self.key, self.key_id = key, key_id

    def _sign(self, payload):
        return sign_attestation(payload, key_id=self.key_id, algorithm=ED25519_ALG, private_key=self.key)

    def _receipt(self, effect, attempt_id, op):
        ev = EvidenceRecord(f"EV-op-{op}", "OBSERVED", f"provider://{self.name}/ops/{op}", "executed",
                            attempt_id, self.name).as_record()
        obs = {"status": "ok", "op": op, "evidence": ev}
        att = self._sign(attestation_payload(provider=self.name, effect_id=effect["effect_id"],
                                             attempt_id=attempt_id, statement=OBSERVED, evidence=ev,
                                             outcome="OBSERVED_SUCCESS", provider_operation_id=op,
                                             observation=obs))
        return ProviderReceipt(self.name, effect["effect_id"], attempt_id, op, "OBSERVED_SUCCESS", obs, att)

    def reconcile(self, *, effect, attempt_id):
        verdict = "APPLIED" if attempt_id in self.applied else "NOT_APPLIED"
        ev = _ev(effect, verdict)
        receipt = self._receipt(effect, attempt_id, self.applied[attempt_id]) if verdict == "APPLIED" else None
        att = self._sign(attestation_payload(provider=self.name, effect_id=effect["effect_id"],
                                             attempt_id=attempt_id, statement=RECONCILED_PREFIX + verdict,
                                             evidence=ev, outcome="OBSERVED_SUCCESS" if receipt else None))
        return ReconciliationReport(verdict, ev, receipt, att)


def test_ed25519_end_to_end_execute_reconcile_retry(tmp_path, monkeypatch, ed):
    key, pub = ed()
    _ed_store(monkeypatch, ("ed1", pub))
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=2)
    done = execute(aios, cid, pid, "op-ok", ACTOR, EdProvider(key, "ed1"))
    stamp = load_receipt(aios, done["receipt_id"], require_provider_signed=True)["source_authenticity"]
    assert stamp == {"level": PROVIDER_SIGNED, "key_id": "ed1", "algorithm": ED25519_ALG,
                     "trust_boundary": INDEPENDENT}
    eff = execute(aios, cid, pid, "op-timeout", ACTOR, EdProvider(key, "ed1", "timeout"))
    rec = runtime.reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, EdProvider(key, "ed1"))
    assert rec["verdict"] == "NOT_APPLIED" and rec["source_authenticity"]["trust_boundary"] == INDEPENDENT
    assert retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", PROVIDER, 2,
                          {"mode": "EXPLICIT", "effect_id": eff["effect_id"], "attempt": 2})["state"] == "DISPATCHED"


def _payload(statement="OBSERVED", **over):
    ev = EvidenceRecord("EV-1", "OBSERVED", "provider://x", "c", "EF-1:attempt:1", PROVIDER).as_record()
    kw = dict(provider=PROVIDER, effect_id="EF-1", attempt_id="EF-1:attempt:1", statement=statement,
              evidence=ev, outcome="OBSERVED_SUCCESS", provider_operation_id="op")
    kw.update(over)
    return attestation_payload(**kw)


def test_ed25519_rejects_wrong_key_tampered_signature_and_other_statement(monkeypatch, ed):
    key, pub = ed()
    other, _ = ed()
    _ed_store(monkeypatch, ("ed1", pub))
    good = sign_attestation(_payload(), key_id="ed1", algorithm=ED25519_ALG, private_key=key)
    assert verify_attestation(good, _payload())["trust_boundary"] == INDEPENDENT
    wrong_key = sign_attestation(_payload(), key_id="ed1", algorithm=ED25519_ALG, private_key=other)
    flipped = good["signature"][:-1] + ("0" if good["signature"][-1] != "0" else "1")
    for bad, payload in [(wrong_key, _payload()),
                         ({**good, "signature": flipped}, _payload()),
                         ({**good, "signature": good["signature"][:-2]}, _payload()),
                         ({**good, "signature": "zz" * 64}, _payload()),
                         ({**good, "key_id": "ed-unknown"}, _payload()),
                         ({**good, "algorithm": "HMAC-SHA256"}, _payload()),
                         (good, _payload(outcome="OBSERVED_FAILURE")),
                         (good, _payload(statement="RECONCILED:NOT_APPLIED", outcome=None,
                                         provider_operation_id=None))]:
        with pytest.raises(ProviderTrustError):
            verify_attestation(bad, payload)


def test_ed25519_key_rotation_old_key_revoked_after_removal(tmp_path, monkeypatch, ed):
    old, old_pub = ed()
    new, new_pub = ed()
    _ed_store(monkeypatch, ("old", old_pub), ("new", new_pub))
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    signed_old = execute(aios, cid, pid, "op-old", ACTOR, EdProvider(old, "old"))
    eff = execute(aios, cid, pid, "op-t", ACTOR, EdProvider(old, "old", "timeout"))
    runtime.reconcile_unknown_attempt(aios, eff["effect_id"], ACTOR, EdProvider(old, "old"))
    assert receipt_source_authenticity(load_receipt(aios, signed_old["receipt_id"])) == PROVIDER_SIGNED
    _ed_store(monkeypatch, ("new", new_pub))  # rotation complete: old key retired
    with pytest.raises(ProviderTrustError, match="not trusted"):
        load_receipt(aios, signed_old["receipt_id"])
    with pytest.raises(ProviderTrustError, match="not trusted"):
        retry_dispatch(aios, eff["effect_id"], ACTOR, f"{eff['effect_id']}:attempt:2", PROVIDER, 2,
                       {"mode": "EXPLICIT", "effect_id": eff["effect_id"], "attempt": 2})
    signed_new = execute(aios, cid, pid, "op-new", ACTOR, EdProvider(new, "new"))
    assert load_receipt(aios, signed_new["receipt_id"])["source_authenticity"]["key_id"] == "new"
    # a retired key cannot sign new statements either
    late = execute(aios, cid, pid, "op-late", ACTOR, EdProvider(old, "old"))
    assert late["state"] == "UNKNOWN" and "not authenticated" in late["unknown_reason"]


@pytest.mark.parametrize("spec", [{"public_key": "ab" * 31}, {"public_key": "zz" * 32},
                                  {"public_key": "ab" * 32, "trust_boundary": "in-process"}])
def test_malformed_ed25519_key_spec_fails_closed(monkeypatch, spec):
    monkeypatch.setenv(TRUST_ENV, json.dumps({"providers": {PROVIDER: [
        {"key_id": "ed1", "algorithm": ED25519_ALG, **spec}]}}))
    with pytest.raises(ProviderTrustError):
        trusted_keys(PROVIDER)
