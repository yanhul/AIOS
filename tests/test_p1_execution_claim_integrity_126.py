"""Adversarial regression tests for PR #126 execution claim integrity and effect path IDs."""
import json
import os

import pytest

import core.effect_authority as ea
from core.effect_authority import dispatch
from core.mutation import TransitionError
from core.record_seal import SealError, SEAL_ENV
from core.runtime import _claim_execution, _observe_invoked
from tests.test_m6_runtime import setup_authority
from tests.test_p0_receipt_lineage_crash_recovery import ACTOR, PROVIDER


def _dispatched(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    effect = ea.create_effect(aios, cid, "claim-integrity", ACTOR, pid, "external_effect")
    effect = dispatch(aios, effect["effect_id"], ACTOR,
                      f"{effect['effect_id']}:attempt:1", PROVIDER)
    return aios, effect


def test_effect_id_is_validated_before_any_effect_path_is_built(tmp_path):
    with pytest.raises(ValueError, match="well-formed effect id"):
        ea._load_current_cas(str(tmp_path), "../contracts/attacker")


def test_unsigned_forged_execution_claim_cannot_authorize_invoked_observation(tmp_path):
    aios, effect = _dispatched(tmp_path)
    rel = ea._claim_relpath(effect["effect_id"], effect["attempt"])
    path = os.path.join(aios, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    forged = {
        "record_type": "EXECUTION_CLAIM",
        "kind": "execution_claim",
        "effect_id": effect["effect_id"],
        "attempt": effect["attempt"],
        "attempt_id": effect["attempt_id"],
        "provider": effect["provider"],
        "actor": ACTOR,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(forged, fh)
    with pytest.raises(SealError):
        _observe_invoked(aios, effect["effect_id"], ACTOR, "OBSERVED_SUCCESS", {"observation": {"ok": True}})
    assert ea._load_current(aios, effect["effect_id"])["state"] == "DISPATCHED"


def test_execution_claim_writer_fails_closed_without_deployment_key(tmp_path, monkeypatch):
    aios, effect = _dispatched(tmp_path)
    # Load and validate the persisted effect while its authority key is present.
    # Then remove the key so this test isolates the claim writer's fail-closed seal.
    current, digest = ea._load_current_cas(aios, effect["effect_id"])
    monkeypatch.delenv(SEAL_ENV, raising=False)
    with pytest.raises(SealError):
        _claim_execution(aios, current, digest, ACTOR)
    assert not os.path.exists(os.path.join(aios, ea._claim_relpath(effect["effect_id"], 1)))
