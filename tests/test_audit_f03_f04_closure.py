# AIOS-CONTRACT: retry authority is signed by a deployment-registered issuer and bound to the exact
#                UNKNOWN effect state; OBSERVED_* is reachable only via observe() with AIOS-minted evidence.
# AIOS-REGRESSION: Audit F-03 (string issuer, unauthenticated digest, mutable consumed state) and
#                  F-04 (transition() observation bypass, optional raw observation, promoted evidence).
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Adversarial issuer/consumption/evidence forgery and replay paths.
# AIOS-BASELINE: Extends tests/test_audit_p1_p2_hardening.py.

import json
import os
import threading

import pytest

from core import effect_authority as ea
from core.effect_authority import (
    RETRY_APPROVE_SCOPE, RETRY_KEYRING_ENV, RetryIssuerKeyring, dispatch, issue_retry_authorization,
    observe, retry_dispatch, transition, unknown,
)
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.runtime import execute_retry_attempt
from tests.retry_issuers import ISSUER_SECRETS, KEYRING, signed_retry_auth
from tests.test_m6_effect_authority import _effect
from tests.test_m6_runtime import setup_authority

ACTOR = "agent-1"
PROVIDER = "provider-1"


def _aid(effect, n):
    return f"{effect['effect_id']}:attempt:{n}"


def _unknown(tmp_path, effect):
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 1), PROVIDER)
    return unknown(str(tmp_path), effect["effect_id"], ACTOR, "timeout")


def _state(tmp_path, effect):
    return ea._load(ea._path(str(tmp_path), effect["effect_id"]))


def _auth_path(tmp_path, auth, consumed=False):
    suffix = ".consumed.json" if consumed else ".json"
    return os.path.join(str(tmp_path), ea.RETRY_AUTH_DIR, auth["authorization_id"] + suffix)


def _rewrite(path, mutate):
    with open(path, encoding="utf-8") as fh:
        rec = json.load(fh)
    mutate(rec)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh)


def _retry(tmp_path, effect, auth, attempt=2, actor=ACTOR, **kw):
    return retry_dispatch(str(tmp_path), effect["effect_id"], actor, _aid(effect, attempt), PROVIDER, attempt, auth, **kw)


# --- F-03: issuer authentication / authorization ---------------------------

def test_f03_arbitrary_unregistered_issuer_rejected(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    with pytest.raises(TransitionError, match="not registered"):
        issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:nobody", "r",
                                  issuer_secret="anything-at-all-123", keyring=KEYRING)
    assert not os.path.isdir(os.path.join(str(tmp_path), ea.RETRY_AUTH_DIR))


def test_f03_unauthenticated_issuer_wrong_secret_rejected(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    with pytest.raises(TransitionError, match="failed authentication"):
        issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r",
                                  issuer_secret="guessed-secret-value", keyring=KEYRING)


@pytest.mark.parametrize("issuer,match", [("operator:readonly", "not authorized"), ("operator:revoked", "revoked")])
def test_f03_unauthorized_or_revoked_issuer_rejected(tmp_path, issuer, match):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    secret = {"operator:readonly": "readonly-operator-secret", "operator:revoked": "revoked-operator-secret"}[issuer]
    with pytest.raises(TransitionError, match=match):
        issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, issuer, "r",
                                  issuer_secret=secret, keyring=KEYRING)


def test_f03_revocation_after_issuance_blocks_consumption(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    revoked = RetryIssuerKeyring({"operator:x": {"secret": ISSUER_SECRETS["operator:x"],
                                                 "scopes": [RETRY_APPROVE_SCOPE], "revoked": True}})
    with pytest.raises(TransitionError, match="revoked"):
        _retry(tmp_path, effect, auth, keyring=revoked)
    assert _state(tmp_path, effect)["state"] == "UNKNOWN"


def test_f03_self_approval_rejected_even_if_actor_holds_a_key(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    ring = RetryIssuerKeyring({ACTOR: {"secret": "actor-owns-a-key-0001", "scopes": [RETRY_APPROVE_SCOPE]}})
    with pytest.raises(TransitionError, match="self-approval"):
        issue_retry_authorization(str(tmp_path), effect["effect_id"], ACTOR, 2, ACTOR, "r",
                                  issuer_secret="actor-owns-a-key-0001", keyring=ring)


def test_f03_missing_trust_anchor_fails_closed(tmp_path, monkeypatch):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    monkeypatch.delenv(RETRY_KEYRING_ENV)
    with pytest.raises(TransitionError, match="trusted issuer keyring"):
        _retry(tmp_path, effect, auth)
    assert _state(tmp_path, effect)["state"] == "UNKNOWN"


def test_f03_keyring_never_leaks_secrets():
    assert "secret" not in repr(KEYRING) and ISSUER_SECRETS["operator:x"] not in repr(KEYRING)


def test_f03_issued_record_contains_no_secret(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    with open(_auth_path(tmp_path, auth), encoding="utf-8") as fh:
        assert ISSUER_SECRETS["operator:x"] not in fh.read()


# --- F-03: context binding --------------------------------------------------

def test_f03_wrong_effect_rejected(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    other = ea.create_effect(str(tmp_path), effect["contract_id"], "op-2", ACTOR, effect["permit_id"], "external_effect")
    _unknown(tmp_path, other)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    with pytest.raises(TransitionError, match="effect_id binding"):
        _retry(tmp_path, other, auth)
    assert _state(tmp_path, other)["state"] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("contract_id", "C-forged"), ("permit_id", "P-forged"),
                                         ("actor", "agent-2"), ("attempt", 3), ("issuer", "operator:test"),
                                         ("expires_at", 9e18), ("effect_state_digest", "0" * 64)])
def test_f03_tampered_signed_field_rejected(tmp_path, field, value):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    _rewrite(_auth_path(tmp_path, auth), lambda rec: rec.__setitem__(field, value))
    with pytest.raises(TransitionError, match="integrity"):
        _retry(tmp_path, effect, auth["authorization_id"])
    assert _state(tmp_path, effect)["state"] == "UNKNOWN"


def test_f03_supplied_dict_with_wrong_contract_rejected(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    with pytest.raises(TransitionError, match="differs from issued record: contract_id"):
        _retry(tmp_path, effect, {**auth, "contract_id": "C-forged"})


def test_f03_wrong_actor_rejected(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    with pytest.raises(TransitionError, match="actor"):
        _retry(tmp_path, effect, auth, actor="agent-2")


def test_f03_wrong_attempt_rejected(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    with pytest.raises(TransitionError, match="attempt"):
        _retry(tmp_path, effect, auth, attempt=3)


def test_f03_expired_authorization_rejected(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r",
                             ttl_seconds=10, now=1_000_000.0)
    with pytest.raises(TransitionError, match="expired"):
        _retry(tmp_path, effect, auth, now=1_000_011.0)
    assert _retry(tmp_path, effect, auth, now=1_000_005.0)["state"] == "DISPATCHED"


def test_f03_state_change_after_issuance_invalidates_authorization(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    _rewrite(ea._path(str(tmp_path), effect["effect_id"]), lambda rec: rec.__setitem__("unknown_reason", "edited"))
    with pytest.raises(TransitionError, match="binding mismatch"):
        _retry(tmp_path, effect, auth)


# --- F-03: single use / tamper-resistant consumption -----------------------

def test_f03_replay_after_consumption_rejected(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    _retry(tmp_path, effect, auth)
    unknown(str(tmp_path), effect["effect_id"], ACTOR, "timeout again")
    with pytest.raises(TransitionError):
        _retry(tmp_path, effect, auth)
    with pytest.raises(TransitionError):
        _retry(tmp_path, effect, auth, attempt=3)


def test_f03_rollback_of_effect_record_cannot_replay(tmp_path):
    effect = _effect(tmp_path)
    snapshot = _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    _retry(tmp_path, effect, auth)
    with open(ea._path(str(tmp_path), effect["effect_id"]), "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh)  # attacker rolls the effect back to the authorized UNKNOWN state
    with pytest.raises(TransitionError, match="already consumed"):
        _retry(tmp_path, effect, auth)


def test_f03_deleting_consumption_record_cannot_replay(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    _retry(tmp_path, effect, auth)
    unknown(str(tmp_path), effect["effect_id"], ACTOR, "timeout again")
    os.unlink(_auth_path(tmp_path, auth, consumed=True))
    with pytest.raises(TransitionError, match="consumption"):
        _retry(tmp_path, effect, auth)


@pytest.mark.parametrize("field,value", [("consumed_provider", "provider-evil"),
                                         ("consumed_by_attempt_id", "forged"), ("authorization_signature", "0" * 64)])
def test_f03_tampered_consumption_record_rejected(tmp_path, field, value):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    _retry(tmp_path, effect, auth)
    unknown(str(tmp_path), effect["effect_id"], ACTOR, "timeout again")
    _rewrite(_auth_path(tmp_path, auth, consumed=True), lambda rec: rec.__setitem__(field, value))
    with pytest.raises(TransitionError, match="consumption record failed integrity"):
        signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 3, "operator:x", "r")


@pytest.mark.parametrize("round_", range(5))
def test_f03_concurrent_consumers_at_most_one_dispatch(tmp_path, round_):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    barrier = threading.Barrier(8)
    results = []

    def worker():
        barrier.wait()
        try:
            _retry(tmp_path, effect, auth)
            results.append("ok")
        except (TransitionError, ValueError, KeyError):
            results.append("rejected")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1, results
    assert _state(tmp_path, effect)["consumed_retry_authorizations"] == [auth["authorization_id"]]


def test_f03_runtime_rejects_caller_built_explicit_mode(tmp_path):
    _c, cid, pid = setup_authority(tmp_path, max_attempts=2)
    effect = ea.create_effect(str(tmp_path), cid, "op-1", "agent:test", pid, "external_effect")
    dispatch(str(tmp_path), effect["effect_id"], "agent:test", _aid(effect, 1), "fake-provider")
    effect = unknown(str(tmp_path), effect["effect_id"], "agent:test", "timeout")
    effect["retry_authorization"] = {"mode": "EXPLICIT", "effect_id": effect["effect_id"], "attempt": 2}

    class Adapter:
        name = "fake-provider"
        calls = 0

        def execute(self, **_):
            Adapter.calls += 1
            raise AssertionError("must not execute")

    with pytest.raises(TransitionError, match="AIOS-issued"):
        execute_retry_attempt(str(tmp_path), cid, pid, effect, "agent:test", Adapter(), _aid(effect, 2), 2)
    assert Adapter.calls == 0


# --- F-04: observation authority boundary ----------------------------------

def _obs(effect, attempt=1, **extra):
    base = {"effect_id": effect["effect_id"], "attempt_id": _aid(effect, attempt), "provider": PROVIDER,
            "provider_operation_id": "op-1", "observation": {"status": "ok"}}
    base.update(extra)
    return base


@pytest.mark.parametrize("target", ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"])
def test_f04_direct_transition_to_observed_rejected(tmp_path, target):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 1), PROVIDER)
    with pytest.raises(TransitionError, match="only be recorded through observe"):
        transition(str(tmp_path), effect["effect_id"], target, ACTOR, provider_observation=_obs(effect))
    with pytest.raises(TransitionError, match="only be recorded through observe"):
        transition(str(tmp_path), effect["effect_id"], target, ACTOR)
    assert _state(tmp_path, effect)["state"] == "DISPATCHED"


@pytest.mark.parametrize("raw", [None, {}, [], "ok", {"x": float("nan")}, {"x": object()}])
def test_f04_missing_empty_or_malformed_observation_rejected(tmp_path, raw):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 1), PROVIDER)
    obs = _obs(effect)
    if raw is None:
        del obs["observation"]
    else:
        obs["observation"] = raw
    with pytest.raises(ValueError, match="observation"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", obs)
    assert _state(tmp_path, effect)["state"] == "DISPATCHED"


def test_f04_wrong_run_id_rejected(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 1), PROVIDER)
    with pytest.raises(TransitionError, match="attempt"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(effect, attempt=2))
    bad = ea.mint_observation_evidence(effect["effect_id"], "other-run", PROVIDER, "op-1", {"status": "ok"})
    with pytest.raises(ValueError, match="run_id"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(effect, evidence=bad))


def test_f04_wrong_artifact_digest_rejected(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 1), PROVIDER)
    ev = ea.mint_observation_evidence(effect["effect_id"], _aid(effect, 1), PROVIDER, "op-1", {"status": "other"})
    with pytest.raises(ValueError, match="artifact_ref"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(effect, evidence=ev))


def test_f04_replay_of_previous_attempt_observation_rejected(tmp_path):
    effect = _effect(tmp_path)
    _unknown(tmp_path, effect)
    _retry(tmp_path, effect, signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r"))
    old = _obs(effect, attempt=1)
    old["evidence"] = ea.mint_observation_evidence(effect["effect_id"], _aid(effect, 1), PROVIDER, "op-1", {"status": "ok"})
    with pytest.raises(TransitionError, match="attempt"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", old)
    with pytest.raises(ValueError, match="run_id"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", {**old, "attempt_id": _aid(effect, 2)})


def test_f04_provider_supplied_fake_evidence_never_becomes_authority(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 1), PROVIDER)
    raw = {"status": "ok"}
    minted = ea.mint_observation_evidence(effect["effect_id"], _aid(effect, 1), PROVIDER, "op-1", raw)
    fake = EvidenceRecord(evidence_id="EV-provider", level="VERIFIED_DIGITAL", source_ref="provider://self",
                          claim="verified by provider", run_id=_aid(effect, 1), provider=PROVIDER,
                          artifact_ref=minted["artifact_ref"]).as_record()  # digest-valid, correctly bound
    with pytest.raises(ValueError, match="AIOS-minted"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(effect, evidence=fake))
    with pytest.raises(ValueError, match="unsupported fields"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", _obs(effect, aios_evidence=fake))
    assert _state(tmp_path, effect)["state"] == "DISPATCHED"


def test_f04_valid_runtime_observation_succeeds_with_minted_evidence(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 1), PROVIDER)
    raw = {"status": "ok", "evidence": {"evidence_id": "EV-smuggled", "level": "PROMOTED"}}
    done = observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_FAILURE", _obs(effect, observation=raw))
    assert done["state"] == "OBSERVED_FAILURE"
    ev = done["provider_observation"]["evidence"]
    assert ev == ea.mint_observation_evidence(effect["effect_id"], _aid(effect, 1), PROVIDER, "op-1", raw)
    assert ev["level"] == "OBSERVED" and ev["artifact_ref"] == ea.observation_digest(raw)
    assert done["provider_observation"]["evidence_authority"] == ea.EVIDENCE_AUTHORITY
