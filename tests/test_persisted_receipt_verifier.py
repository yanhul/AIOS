"""Restart-time independent verification of persisted provider receipts."""
import json

import pytest

from core.effect_authority import dispatch, observe
from core.mutation import TransitionError
from core.receipt_verifier import PersistedReceiptError, verify_persisted_receipt
from tests.provider_keys import KEYRING, sign_observation
from tests.test_m6_effect_authority import _effect, _observation


def _terminal(tmp_path):
    effect = _effect(tmp_path)
    attempt_id = f"{effect['effect_id']}:attempt:1"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", attempt_id, "provider-1")
    supplied = sign_observation(effect, _observation(effect["effect_id"]))
    done = observe(
        str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS",
        supplied, provider_keyring=KEYRING,
    )
    return done, supplied["authentication"]["receipt_id"]


def test_persisted_receipt_is_independently_verified_after_reload(tmp_path):
    done, receipt_id = _terminal(tmp_path)
    # Re-open the persisted state rather than relying on the object returned by observe().
    result = verify_persisted_receipt(
        str(tmp_path), receipt_id, "agent-1", provider_keyring=KEYRING,
    )
    assert result["verified"] is True
    assert result["effect_id"] == done["effect_id"]
    assert result["attempt_id"] == done["attempt_id"]
    assert result["outcome"] == "OBSERVED_SUCCESS"


def test_persisted_receipt_tampering_is_rejected(tmp_path):
    _done, receipt_id = _terminal(tmp_path)
    path = tmp_path / "provider_receipts" / (receipt_id + ".json")
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["observation"] = {"status": "forged"}
    path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(PersistedReceiptError, match="digest mismatch"):
        verify_persisted_receipt(str(tmp_path), receipt_id, "agent-1", provider_keyring=KEYRING)


def test_persisted_receipt_requires_deployment_trust_anchor(tmp_path, monkeypatch):
    _done, receipt_id = _terminal(tmp_path)
    monkeypatch.delenv("AIOS_PROVIDER_KEYRING", raising=False)
    with pytest.raises(PersistedReceiptError, match="deployment-supplied trusted provider keyring"):
        verify_persisted_receipt(str(tmp_path), receipt_id, "agent-1")
