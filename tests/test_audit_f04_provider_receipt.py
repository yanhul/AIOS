# AIOS-CONTRACT: OBSERVED_* is committed only for a receipt signed by the DISPATCHED provider's
#                deployment-registered key and bound to effect/contract/permit/attempt/provider/
#                operation/outcome/raw-observation digest within a validity window.
# AIOS-REGRESSION: Audit F-04 follow-up — caller-fabricated observations promoted to OBSERVED_*.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Fabrication, impersonation, rebinding, replay, expiry, missing trust anchor, races.
# AIOS-BASELINE: Extends tests/test_audit_f03_f04_closure.py.

import threading

import pytest

from core import effect_authority as ea
from core.effect_authority import (
    PROVIDER_KEYRING_ENV, PROVIDER_RECEIPT_SCOPE, ProviderAuthenticationError, ProviderKeyring, dispatch,
    observe, provider_receipt_body, provider_receipt_signature, retry_dispatch, transition, unknown,
)
from core.mutation import TransitionError
from core.runtime import ProviderReceipt, execute
from tests.provider_keys import SECRETS, sign_observation, signed
from tests.retry_issuers import signed_retry_auth
from tests.test_m6_effect_authority import _effect
from tests.test_m6_runtime import setup_authority

ACTOR = "agent-1"
PROVIDER = "provider-1"
T0 = 1_000_000.0


def _aid(effect, n=1):
    return f"{effect['effect_id']}:attempt:{n}"


def _dispatched(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect), PROVIDER)
    return effect


def _obs(effect, attempt=1, **extra):
    base = {"effect_id": effect["effect_id"], "attempt_id": _aid(effect, attempt), "provider": PROVIDER,
            "provider_operation_id": "op-1", "observation": {"status": "ok"}}
    base.update(extra)
    return base


def _state(tmp_path, effect):
    return ea._load(ea._path(str(tmp_path), effect["effect_id"]))


def _rejected(tmp_path, effect, obs, outcome="OBSERVED_SUCCESS", exc=ProviderAuthenticationError, match=None, **kw):
    with pytest.raises(exc, match=match):
        observe(str(tmp_path), effect["effect_id"], ACTOR, outcome, obs, **kw)
    assert _state(tmp_path, effect)["state"] == "DISPATCHED"


def test_valid_signed_receipt_is_authoritative(tmp_path):
    effect = _dispatched(tmp_path)
    done = observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", sign_observation(effect, _obs(effect)))
    assert done["state"] == "OBSERVED_SUCCESS"
    po = done["provider_observation"]
    assert po["provider_authentication"]["contract_id"] == effect["contract_id"]
    assert po["evidence"]["run_id"] == _aid(effect) and po["evidence_authority"] == ea.EVIDENCE_AUTHORITY
    with open(ea._path(str(tmp_path), effect["effect_id"]), encoding="utf-8") as fh:
        assert SECRETS[PROVIDER] not in fh.read()  # signing key never persisted


def test_caller_fabricated_unsigned_success_rejected(tmp_path):
    effect = _dispatched(tmp_path)
    _rejected(tmp_path, effect, _obs(effect), match="not authenticated")


def test_caller_supplied_aios_evidence_is_not_proof_of_execution(tmp_path):
    effect = _dispatched(tmp_path)
    ev = ea.mint_observation_evidence(effect["effect_id"], _aid(effect), PROVIDER, "op-1", {"status": "ok"})
    _rejected(tmp_path, effect, _obs(effect, evidence=ev), match="not authenticated")


def test_caller_forged_signature_with_guessed_key_rejected(tmp_path):
    effect = _dispatched(tmp_path)
    _rejected(tmp_path, effect, sign_observation(effect, _obs(effect), secret="attacker-chosen-secret-key"),
              match="signature is invalid")


def test_impersonating_dispatched_provider_with_another_providers_key_rejected(tmp_path):
    effect = _dispatched(tmp_path)
    forged = sign_observation(effect, _obs(effect), secret=SECRETS["provider-2"])  # provider-2 claims provider-1
    _rejected(tmp_path, effect, forged, match="signature is invalid")
    other = sign_observation(effect, _obs(effect, provider="provider-2"))  # honest provider-2 receipt
    _rejected(tmp_path, effect, other, exc=TransitionError, match="provider does not match")


def test_receipt_with_mismatched_attempt_rejected(tmp_path):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect))
    _rejected(tmp_path, effect, {**good, "attempt_id": _aid(effect, 2)}, exc=TransitionError, match="attempt")
    other_attempt = sign_observation(effect, _obs(effect, attempt=2))
    _rejected(tmp_path, effect, {**other_attempt, "attempt_id": _aid(effect, 1)}, match="signature is invalid")


def test_receipt_with_mismatched_effect_rejected(tmp_path):
    effect = _dispatched(tmp_path)
    other = ea.create_effect(str(tmp_path), effect["contract_id"], "op-2", ACTOR, effect["permit_id"], "external_effect")
    dispatch(str(tmp_path), other["effect_id"], ACTOR, _aid(other), PROVIDER)
    receipt_for_other = sign_observation(other, _obs(other))
    rebound = {**receipt_for_other, "effect_id": effect["effect_id"], "attempt_id": _aid(effect)}
    _rejected(tmp_path, effect, rebound, match="signature is invalid")


@pytest.mark.parametrize("field", ["contract_id", "permit_id"])
def test_receipt_with_mismatched_contract_or_permit_rejected(tmp_path, field):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect))
    bad = {**good, "authentication": {**good["authentication"], field: "forged"}}
    _rejected(tmp_path, effect, bad, match=f"{field} binding mismatch")
    signed_for_other = sign_observation({**effect, field: "forged"}, _obs(effect))
    _rejected(tmp_path, effect, signed_for_other, match=f"{field} binding mismatch")


def test_receipt_digest_differs_from_raw_observation_rejected(tmp_path):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect))
    _rejected(tmp_path, effect, {**good, "observation": {"status": "tampered"}}, match="signature is invalid")
    _rejected(tmp_path, effect, {**good, "provider_operation_id": "op-other"}, match="signature is invalid")


def test_receipt_outcome_cannot_be_flipped(tmp_path):
    effect = _dispatched(tmp_path)
    failure = sign_observation(effect, _obs(effect), "OBSERVED_FAILURE")
    _rejected(tmp_path, effect, failure, outcome="OBSERVED_SUCCESS", match="signature is invalid")


def test_receipt_replay_across_attempts_rejected(tmp_path):
    effect = _dispatched(tmp_path)
    attempt1 = sign_observation(effect, _obs(effect))
    unknown(str(tmp_path), effect["effect_id"], ACTOR, "timeout")
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r")
    retry_dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 2), PROVIDER, 2, auth)
    _rejected(tmp_path, effect, attempt1, exc=TransitionError, match="attempt")
    _rejected(tmp_path, effect, {**attempt1, "attempt_id": _aid(effect, 2)}, match="signature is invalid")


def test_terminal_receipt_cannot_be_replayed(tmp_path):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect))
    observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", good)
    with pytest.raises(TransitionError, match="DISPATCHED"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", good)


def test_expired_or_future_receipt_rejected(tmp_path):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect), now=T0, ttl_seconds=60)
    _rejected(tmp_path, effect, good, match="expired", now=T0 + 61)
    _rejected(tmp_path, effect, good, match="future", now=T0 - 3600)
    assert observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", good, now=T0 + 30)["state"] \
        == "OBSERVED_SUCCESS"


def test_overlong_validity_window_rejected_even_if_signed(tmp_path):
    effect = _dispatched(tmp_path)
    obs = _obs(effect)
    auth = {"type": ea.PROVIDER_RECEIPT_TYPE, "receipt_id": "PR-" + "a" * 32, "contract_id": effect["contract_id"],
            "permit_id": effect["permit_id"], "issued_at": T0, "expires_at": T0 + 10 ** 7, "algorithm": "HMAC-SHA256"}
    body = provider_receipt_body(receipt_id=auth["receipt_id"], effect_id=effect["effect_id"],
                                 contract_id=effect["contract_id"], permit_id=effect["permit_id"],
                                 attempt_id=obs["attempt_id"], provider=PROVIDER, provider_operation_id="op-1",
                                 outcome="OBSERVED_SUCCESS", observation=obs["observation"],
                                 issued_at=T0, expires_at=auth["expires_at"])
    auth["signature"] = provider_receipt_signature(SECRETS[PROVIDER].encode(), body)
    _rejected(tmp_path, effect, {**obs, "authentication": auth}, match="validity window", now=T0 + 1)


@pytest.mark.parametrize("mutate", [
    lambda a: a.update(extra="x"), lambda a: a.pop("receipt_id"), lambda a: a.update(algorithm="none"),
    lambda a: a.update(receipt_id="PR-short"), lambda a: a.update(issued_at="now"),
])
def test_malformed_authentication_rejected(tmp_path, mutate):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect))
    auth = dict(good["authentication"])
    mutate(auth)
    _rejected(tmp_path, effect, {**good, "authentication": auth})


def test_missing_trusted_provider_keyring_fails_closed(tmp_path, monkeypatch):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect))
    monkeypatch.delenv(PROVIDER_KEYRING_ENV)
    _rejected(tmp_path, effect, good, match="trusted provider keyring")


def test_unregistered_unscoped_or_revoked_provider_rejected(tmp_path):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect))
    secret = SECRETS[PROVIDER]
    for ring, match in ((ProviderKeyring({"someone-else": {"secret": secret, "scopes": [PROVIDER_RECEIPT_SCOPE]}}),
                         "not registered"),
                        (ProviderKeyring({PROVIDER: {"secret": secret, "scopes": ["other.scope"]}}), "not authorized"),
                        (ProviderKeyring({PROVIDER: {"secret": secret, "scopes": [PROVIDER_RECEIPT_SCOPE],
                                                     "revoked": True}}), "revoked")):
        _rejected(tmp_path, effect, good, match=match, provider_keyring=ring)


@pytest.mark.parametrize("target", ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"])
def test_direct_generic_transition_rejected_even_with_valid_receipt(tmp_path, target):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect), target)
    with pytest.raises(TransitionError, match="only be recorded through observe"):
        transition(str(tmp_path), effect["effect_id"], target, ACTOR, provider_observation=good)
    assert _state(tmp_path, effect)["state"] == "DISPATCHED"


@pytest.mark.parametrize("round_", range(3))
def test_concurrent_observation_submissions_commit_once(tmp_path, round_):
    effect = _dispatched(tmp_path)
    receipts = [sign_observation(effect, _obs(effect, provider_operation_id=f"op-{i}"),
                                 "OBSERVED_SUCCESS" if i % 2 else "OBSERVED_FAILURE") for i in range(8)]
    barrier = threading.Barrier(8)
    results = []

    def worker(i):
        barrier.wait()
        outcome = "OBSERVED_SUCCESS" if i % 2 else "OBSERVED_FAILURE"
        try:
            observe(str(tmp_path), effect["effect_id"], ACTOR, outcome, receipts[i])
            results.append(("ok", i))
        except TransitionError:
            results.append(("rejected", i))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    winners = [i for status, i in results if status == "ok"]
    assert len(winners) == 1, results
    final = _state(tmp_path, effect)
    assert final["provider_observation"]["provider_operation_id"] == f"op-{winners[0]}"


class _UnsignedAdapter:
    name = "fake-provider"

    def execute(self, *, contract, effect, attempt_id):
        return ProviderReceipt(self.name, effect["effect_id"], attempt_id, "op", "OBSERVED_SUCCESS", {"status": "ok"})


class _ForgingAdapter(_UnsignedAdapter):
    def execute(self, *, contract, effect, attempt_id):
        receipt = super().execute(contract=contract, effect=effect, attempt_id=attempt_id)
        from tests.provider_keys import signer
        from core.provider_authority import authenticate_receipt
        return authenticate_receipt(receipt, effect, signer(self.name, "agent-made-up-signing-key"))


@pytest.mark.parametrize("adapter", [_UnsignedAdapter(), _ForgingAdapter()])
def test_runtime_keeps_unauthenticated_provider_result_unknown(tmp_path, adapter):
    _c, cid, pid = setup_authority(tmp_path)
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    assert result["state"] == "UNKNOWN"
    assert "non-authoritative provider observation" in result["unknown_reason"]
    assert "provider_observation" not in result


def test_runtime_signed_provider_result_is_observed(tmp_path):
    _c, cid, pid = setup_authority(tmp_path)

    class Signed(_UnsignedAdapter):
        def execute(self, *, contract, effect, attempt_id):
            return signed(super().execute(contract=contract, effect=effect, attempt_id=attempt_id), effect)

    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", Signed())
    assert result["state"] == "OBSERVED_SUCCESS"


def test_keyrings_and_signers_never_leak_secrets():
    from tests.provider_keys import KEYRING, signer
    assert SECRETS[PROVIDER] not in repr(KEYRING) and SECRETS[PROVIDER] not in repr(signer(PROVIDER))
