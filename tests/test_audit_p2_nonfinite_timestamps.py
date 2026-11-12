# AIOS-CONTRACT: Receipt/authorization validity windows and the validation clock must be finite numbers.
#                NaN / +Infinity / -Infinity fail closed on every path and never yield an accepted receipt.
# AIOS-REGRESSION: PR #129 review P2 — non-finite timestamps bypass ordinary comparison checks
#                  (NaN compares False everywhere; inf - inf is NaN).
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Ed25519 receipts, HMAC receipts, shared validity window, retry authorizations,
#                    validation clock, canonical serialization.
# AIOS-BASELINE: Extends tests/test_audit_f04_provider_receipt.py and tests/test_audit_f03_f04_closure.py.

import hashlib
import hmac
import json
import os

import pytest

from core import effect_authority as ea
from core import provider_ed25519 as ed
from core.effect_authority import ProviderAuthenticationError, dispatch, observe, retry_dispatch, unknown
from core.mutation import TransitionError, canonical_json
from tests.provider_keys import SECRETS, _ed25519_private, ed25519_keyring_spec, sign_observation
from tests.retry_issuers import ISSUER_SECRETS, signed_retry_auth
from tests.test_m6_effect_authority import _effect

ACTOR = "agent-1"
PROVIDER = "provider-1"
T0 = 1_000_000.0
NAN, INF = float("nan"), float("inf")
NONFINITE = [NAN, INF, -INF]
NONFINITE_IDS = ["nan", "+inf", "-inf"]

# (issued_at, expires_at) pairs; every one has at least one non-finite bound.
BAD_WINDOWS = [
    (NAN, T0 + 60), (T0, NAN), (NAN, NAN),
    (INF, INF), (-INF, -INF), (-INF, INF), (T0, INF), (-INF, T0 + 60), (INF, T0 + 60), (T0, -INF),
]
BAD_WINDOW_IDS = ["nan-issued", "nan-expires", "nan-both", "inf-inf", "ninf-ninf", "ninf-inf",
                  "finite-inf", "ninf-finite", "inf-finite", "finite-ninf"]


def _permissive_canonical(obj):
    """What an attacker's serializer could emit: canonical layout but NaN/Infinity allowed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=True)


def _aid(effect, n=1):
    return f"{effect['effect_id']}:attempt:{n}"


def _state(tmp_path, effect):
    return ea._load(ea._path(str(tmp_path), effect["effect_id"]))


def _dispatched(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect), PROVIDER)
    return effect


def _obs(effect):
    return {"effect_id": effect["effect_id"], "attempt_id": _aid(effect), "provider": PROVIDER,
            "provider_operation_id": "op-1", "observation": {"status": "ok"}}


def _hmac_receipt(effect, issued_at, expires_at):
    """HMAC receipt signed with the REAL provider key over a permissive (NaN-allowing) serialization."""
    obs = _obs(effect)
    auth = {"type": ea.PROVIDER_RECEIPT_TYPE, "receipt_id": "PR-" + "b" * 32, "contract_id": effect["contract_id"],
            "permit_id": effect["permit_id"], "issued_at": issued_at, "expires_at": expires_at,
            "algorithm": "HMAC-SHA256"}
    body = {"type": ea.PROVIDER_RECEIPT_TYPE, "receipt_id": auth["receipt_id"], "effect_id": effect["effect_id"],
            "contract_id": effect["contract_id"], "permit_id": effect["permit_id"], "attempt_id": obs["attempt_id"],
            "provider": PROVIDER, "provider_operation_id": "op-1", "outcome": "OBSERVED_SUCCESS",
            "observation_digest": ea.observation_digest(obs["observation"]),
            "issued_at": issued_at, "expires_at": expires_at, "algorithm": "HMAC-SHA256"}
    signed = {k: body.get(k) for k in ea._PROVIDER_SIGNED_FIELDS}
    auth["signature"] = hmac.new(SECRETS[PROVIDER].encode(), _permissive_canonical(signed).encode("utf-8"),
                                 hashlib.sha256).hexdigest()
    return {**obs, "authentication": auth}


# --- canonical serialization ---------------------------------------------------------------

@pytest.mark.parametrize("value", NONFINITE, ids=NONFINITE_IDS)
def test_canonical_json_rejects_nonfinite(value):
    with pytest.raises(ValueError):
        canonical_json({"issued_at": value})


def test_canonical_json_unchanged_for_finite_values():
    obj = {"b": 1, "a": [1.5, "x", None, True], "c": {"z": 0.0}}
    assert canonical_json(obj) == '{"a":[1.5,"x",null,true],"b":1,"c":{"z":0.0}}'


# --- HMAC provider receipts (shared validity window) ---------------------------------------

def test_hmac_harness_control_finite_window_accepted(tmp_path):
    """Sanity: the permissive-serializer harness produces an accepted receipt for finite bounds."""
    effect = _dispatched(tmp_path)
    rec = _hmac_receipt(effect, T0, T0 + 60)
    assert observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", rec, now=T0 + 1)["state"] \
        == "OBSERVED_SUCCESS"


@pytest.mark.parametrize("issued_at,expires_at", BAD_WINDOWS, ids=BAD_WINDOW_IDS)
def test_hmac_receipt_with_nonfinite_window_fails_closed(tmp_path, issued_at, expires_at):
    effect = _dispatched(tmp_path)
    rec = _hmac_receipt(effect, issued_at, expires_at)
    with pytest.raises(ProviderAuthenticationError, match="malformed"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", rec, now=T0 + 1)
    assert _state(tmp_path, effect)["state"] == "DISPATCHED"


@pytest.mark.parametrize("now", NONFINITE, ids=NONFINITE_IDS)
def test_hmac_valid_receipt_with_nonfinite_validation_clock_fails_closed(tmp_path, now):
    effect = _dispatched(tmp_path)
    good = sign_observation(effect, _obs(effect), now=T0, ttl_seconds=60)
    with pytest.raises(ValueError, match="finite"):
        observe(str(tmp_path), effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", good, now=now)
    assert _state(tmp_path, effect)["state"] == "DISPATCHED"


@pytest.mark.parametrize("issued_at,expires_at", BAD_WINDOWS, ids=BAD_WINDOW_IDS)
def test_shared_validity_window_rejects_nonfinite_bounds(issued_at, expires_at):
    with pytest.raises(ProviderAuthenticationError, match="validity window"):
        ea._check_validity_window({"issued_at": issued_at, "expires_at": expires_at}, T0 + 1)


@pytest.mark.parametrize("now", NONFINITE + [10 ** 400, True], ids=NONFINITE_IDS + ["huge-int", "bool"])
def test_shared_validity_window_rejects_nonfinite_clock(now):
    with pytest.raises(ValueError, match="finite"):
        ea._check_validity_window({"issued_at": T0, "expires_at": T0 + 60}, now)


def test_shared_validity_window_finite_behaviour_preserved():
    ea._check_validity_window({"issued_at": T0, "expires_at": T0 + 60}, T0 + 30)
    with pytest.raises(ProviderAuthenticationError, match="expired"):
        ea._check_validity_window({"issued_at": T0, "expires_at": T0 + 60}, T0 + 61)
    with pytest.raises(ProviderAuthenticationError, match="future"):
        ea._check_validity_window({"issued_at": T0, "expires_at": T0 + 60}, T0 - 3600)


@pytest.mark.parametrize("now", NONFINITE, ids=NONFINITE_IDS)
def test_hmac_signer_refuses_nonfinite_issue_time(tmp_path, now):
    effect = _dispatched(tmp_path)
    with pytest.raises(ValueError):
        sign_observation(effect, _obs(effect), now=now)


# --- Ed25519 provider receipts (F-04.1 path) -----------------------------------------------

pytestmark_ed = pytest.mark.skipif(not ed.ED25519_AVAILABLE, reason="cryptography not installed")


def _ed_current():
    return {"effect_id": "EF-" + "1" * 64, "contract_id": "C-1", "permit_id": "P-1",
            "attempt_id": "EF-" + "1" * 64 + ":attempt:1", "provider": "minimind"}


def _ed_record(issued_at, expires_at, *, label="minimind-workload-test-key"):
    """Ed25519 receipt signed with the REAL registered workload key over a permissive serialization."""
    cur = _ed_current()
    spec = ed25519_keyring_spec(label)
    key_id = spec["minimind"]["key_id"]
    observation = {"terminal_state": "PROMOTE"}
    payload = _permissive_canonical({
        "type": ed.ED25519_RECEIPT_TYPE, "algorithm": ed.ED25519_ALGORITHM, "key_id": key_id,
        "receipt_id": "PR-" + "c" * 32, "effect_id": cur["effect_id"], "contract_id": cur["contract_id"],
        "permit_id": cur["permit_id"], "attempt_id": cur["attempt_id"], "provider": "minimind",
        "provider_operation_id": "op-1", "outcome": "OBSERVED_SUCCESS",
        "receipt_digest": ed.receipt_digest(observation), "issued_at": issued_at, "expires_at": expires_at,
    }).encode("utf-8")
    sig = _ed25519_private(label).sign(payload).hex()
    auth = {"type": ed.ED25519_RECEIPT_TYPE, "algorithm": ed.ED25519_ALGORITHM, "key_id": key_id,
            "receipt_id": "PR-" + "c" * 32, "contract_id": cur["contract_id"], "permit_id": cur["permit_id"],
            "issued_at": issued_at, "expires_at": expires_at, "signature": sig}
    return cur, {"provider_operation_id": "op-1", "observation": observation, "authentication": auth}, \
        ed.ProviderPublicKeyring(spec)


@pytestmark_ed
def test_ed25519_harness_control_finite_window_accepted():
    cur, rec, keyring = _ed_record(T0, T0 + 60)
    auth = ea._verify_provider_receipt(cur, "OBSERVED_SUCCESS", rec, None, T0 + 1, public_keyring=keyring)
    assert auth["receipt_id"] == "PR-" + "c" * 32


@pytestmark_ed
@pytest.mark.parametrize("issued_at,expires_at", BAD_WINDOWS, ids=BAD_WINDOW_IDS)
def test_ed25519_receipt_with_nonfinite_window_fails_closed(issued_at, expires_at):
    cur, rec, keyring = _ed_record(issued_at, expires_at)
    with pytest.raises(ProviderAuthenticationError, match="malformed"):
        ea._verify_provider_receipt(cur, "OBSERVED_SUCCESS", rec, None, T0 + 1, public_keyring=keyring)


@pytestmark_ed
@pytest.mark.parametrize("now", NONFINITE, ids=NONFINITE_IDS)
def test_ed25519_valid_receipt_with_nonfinite_validation_clock_fails_closed(now):
    cur, rec, keyring = _ed_record(T0, T0 + 60)
    with pytest.raises(ValueError, match="finite"):
        ea._verify_provider_receipt(cur, "OBSERVED_SUCCESS", rec, None, now, public_keyring=keyring)


@pytestmark_ed
@pytest.mark.parametrize("issued_at,expires_at", BAD_WINDOWS, ids=BAD_WINDOW_IDS)
def test_ed25519_nonfinite_window_never_reaches_hmac_fallback(issued_at, expires_at):
    """Even with a full HMAC keyring present, a minimind receipt stays Ed25519-only and fails closed."""
    from tests.provider_keys import KEYRING
    cur, rec, keyring = _ed_record(issued_at, expires_at)
    with pytest.raises(ProviderAuthenticationError):
        ea._verify_provider_receipt(cur, "OBSERVED_SUCCESS", rec, KEYRING, T0 + 1, public_keyring=keyring)


# --- Retry authorizations (F-03 validity window) -------------------------------------------

def _unknown_effect(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 1), PROVIDER)
    unknown(str(tmp_path), effect["effect_id"], ACTOR, "timeout")
    return effect


def _resign_with(tmp_path, auth, **fields):
    """Rewrite the persisted record with ``fields`` and re-sign it with the REAL issuer secret."""
    path = os.path.join(str(tmp_path), ea.RETRY_AUTH_DIR, auth["authorization_id"] + ".json")
    with open(path, encoding="utf-8") as fh:
        rec = json.load(fh)
    rec.update(fields)
    body = {k: rec.get(k) for k in ea._RETRY_SIGNED_FIELDS}
    rec["signature"] = hmac.new(ISSUER_SECRETS[rec["issuer"]].encode("utf-8"),
                                _permissive_canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh)  # json.dump emits NaN/Infinity literals; json.load reads them back


def _retry(tmp_path, effect, auth, **kw):
    return retry_dispatch(str(tmp_path), effect["effect_id"], ACTOR, _aid(effect, 2), PROVIDER, 2,
                          auth["authorization_id"], **kw)


def test_retry_harness_control_resigned_finite_record_accepted(tmp_path):
    effect = _unknown_effect(tmp_path)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r", now=T0)
    _resign_with(tmp_path, auth, issued_at=T0, expires_at=T0 + 60)
    assert _retry(tmp_path, effect, auth, now=T0 + 1)["state"] == "DISPATCHED"


@pytest.mark.parametrize("issued_at,expires_at", BAD_WINDOWS, ids=BAD_WINDOW_IDS)
def test_retry_authorization_with_nonfinite_window_fails_closed(tmp_path, issued_at, expires_at):
    effect = _unknown_effect(tmp_path)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r", now=T0)
    _resign_with(tmp_path, auth, issued_at=issued_at, expires_at=expires_at)
    with pytest.raises(TransitionError, match="integrity"):
        _retry(tmp_path, effect, auth, now=T0 + 1)
    assert _state(tmp_path, effect)["state"] == "UNKNOWN"


@pytest.mark.parametrize("now", NONFINITE, ids=NONFINITE_IDS)
def test_retry_authorization_with_nonfinite_validation_clock_fails_closed(tmp_path, now):
    effect = _unknown_effect(tmp_path)
    auth = signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r", now=T0)
    with pytest.raises(ValueError, match="finite"):
        _retry(tmp_path, effect, auth, now=now)
    assert _state(tmp_path, effect)["state"] == "UNKNOWN"


@pytest.mark.parametrize("now", NONFINITE, ids=NONFINITE_IDS)
def test_retry_authorization_cannot_be_issued_at_nonfinite_time(tmp_path, now):
    effect = _unknown_effect(tmp_path)
    with pytest.raises(ValueError, match="finite"):
        signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r", now=now)
    assert not os.path.isdir(os.path.join(str(tmp_path), ea.RETRY_AUTH_DIR)) or not any(
        n.endswith(".json") for n in os.listdir(os.path.join(str(tmp_path), ea.RETRY_AUTH_DIR)))


@pytest.mark.parametrize("ttl", NONFINITE, ids=NONFINITE_IDS)
def test_retry_authorization_rejects_nonfinite_ttl(tmp_path, ttl):
    effect = _unknown_effect(tmp_path)
    with pytest.raises(ValueError, match="ttl_seconds"):
        signed_retry_auth(str(tmp_path), effect["effect_id"], ACTOR, 2, "operator:x", "r", now=T0, ttl_seconds=ttl)
