"""Adversarial integration test for the governed bridge's receipt lineage.

This uses the real effect authority (sealed filesystem records) and a file-backed
loop state store. It documents that the generic durable-loop receipt intent is
not currently mapped to AIOS effect/attempt identities.
"""
import json
import os

import pytest

from core.durable_loop import reconcile_in_flight_attempt
from core.effect_authority import load_receipt
from core.orchestrator import run_governed_execution
from tests.test_p1_governed_bridge_effect_authority_126 import (
    Verifier, _authority, _effect_file, _executor, _policy,
)
from tests.test_p0_receipt_lineage_crash_recovery import Provider


class JsonStateStore:
    """Minimal process-reloadable StateStore; no in-memory state is authoritative."""

    def __init__(self, path):
        self.path = os.fspath(path)

    def load(self):
        if not os.path.exists(self.path):
            return None
        with open(self.path, encoding="utf-8") as stream:
            return json.load(stream)

    def save(self, state):
        temporary = self.path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(state, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)


def test_real_effect_receipt_cannot_reconcile_generic_bridge_intent(tmp_path):
    aios, contract_id, permit_id, digest = _authority(tmp_path / "authority")
    store = JsonStateStore(tmp_path / "loop-state.json")
    provider = Provider()
    policy = _policy(
        digest,
        require_execution_receipt=True,
        execution_receipt_validator=lambda receipt, state: None,
        state_patch_validator=lambda patch, receipt, state: None,
    )

    result = run_governed_execution(
        executor=_executor(aios, contract_id, permit_id, provider, Verifier()),
        store=store,
        policy=policy,
    )

    assert result["status"] == "BLOCKED"
    effect = _effect_file(aios)
    assert effect["state"] == "OBSERVED_SUCCESS"
    receipt = load_receipt(aios, effect["receipt_id"])
    assert receipt["outcome"] == "OBSERVED_SUCCESS"
    assert "status" not in receipt

    reloaded = JsonStateStore(store.path).load()
    intent = reloaded["in_flight_attempt"]
    assert intent["effect_id"] != effect["effect_id"]
    assert intent["attempt_id"] != effect["attempt_id"]

    generic_receipt = {
        "effect_id": receipt["effect_id"],
        "attempt_id": receipt["attempt_id"],
        "status": "OBSERVED",
        "evidence": receipt["evidence"],
    }
    with pytest.raises(ValueError, match="does not match the persisted execution intent"):
        reconcile_in_flight_attempt(
            JsonStateStore(store.path),
            policy,
            generic_receipt,
            authorizer=lambda intent, validated: None,
        )
