# AIOS-CONTRACT: The governed bridge refuses durable-loop receipt mode before any state write or provider call,
#                and never resumes past a persisted durable-loop in-flight intent (PR #126 review comment
#                6761666720, disposition b).
# AIOS-REGRESSION: At 842ebeb, require_execution_receipt=True let the real provider apply the effect (effect authority
#                  OBSERVED_SUCCESS + sealed receipt) and only afterwards fail: the loop's uuid effect-/attempt-
#                  intent does not match EF-/EF-...:attempt:1 and cannot be reconciled with
#                  reconcile_in_flight_attempt(). Receipts for this bridge are enforced by the effect authority gate.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Disposition (a), mapping loop intent/receipt/recovery to effect-authority ids, is not
#                    implemented; receipt mode with this bridge is unsupported rather than integrated. Process
#                    death is simulated by persisting the pre-crash loop snapshot to the file-backed store.
# AIOS-BASELINE: 842ebeb (642 passed, 1 skipped)
"""Adversarial integration test for the governed bridge's receipt lineage.

Real effect authority (sealed filesystem records) and a file-backed, process-reloadable loop store.
Originally written by the independent reviewer at 842ebeb to document the lineage gap; updated for the
chosen disposition: refuse the unsupported policy combination before the provider is invoked.
"""
import json
import os

import pytest

from core.durable_loop import reconcile_in_flight_attempt
from core.effect_authority import load_receipt
from core.orchestrator import run_governed_execution
from core.runtime import execute
from tests.test_p0_receipt_lineage_crash_recovery import ACTOR
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


def _receipt_mode_policy(digest):
    return _policy(
        digest,
        require_execution_receipt=True,
        execution_receipt_validator=lambda receipt, state: None,
        state_patch_validator=lambda patch, receipt, state: None,
    )


def test_receipt_mode_is_refused_before_provider_and_before_any_loop_state(tmp_path):
    aios, contract_id, permit_id, digest = _authority(tmp_path / "authority")
    store = JsonStateStore(tmp_path / "loop-state.json")
    provider = Provider()
    with pytest.raises(PermissionError, match="durable-loop receipt mode"):
        run_governed_execution(executor=_executor(aios, contract_id, permit_id, provider, Verifier()),
                               store=store, policy=_receipt_mode_policy(digest))
    assert provider.calls == 0                                   # no external side effect
    assert not os.path.exists(os.path.join(aios, "effects"))     # no effect authority record
    assert JsonStateStore(store.path).load() is None             # no uuid intent persisted


def test_persisted_loop_intent_after_provider_effect_blocks_duplicate_resume(tmp_path):
    """Crash after the real provider effect, before loop commit: resume must not execute it again."""
    aios, contract_id, permit_id, digest = _authority(tmp_path / "authority")
    store = JsonStateStore(tmp_path / "loop-state.json")
    provider = Provider()
    # Reproduce the dangerous crash window: effect authority has committed a real
    # OBSERVED_SUCCESS + sealed receipt, but the durable loop still has only its
    # pre-provider UUID intent (not the EF-/attempt identity).
    applied = execute(aios, contract_id, permit_id, "op-1", ACTOR, provider)
    assert applied["state"] == "OBSERVED_SUCCESS"
    assert load_receipt(aios, applied["receipt_id"])["outcome"] == "OBSERVED_SUCCESS"
    assert provider.calls == 1
    store.save({  # exactly what the pre-fix bridge persisted just before calling the provider
        "contract_id": contract_id, "permit_id": permit_id, "policy_digest": digest, "step": 0,
        "status": "RUNNING", "history": [],
        "in_flight_attempt": {"effect_id": "effect-" + "0" * 32, "attempt_id": "attempt-" + "0" * 32,
                              "decision": {"logical_operation_id": "op-1"}, "observation": {"ready": True},
                              "status": "PREPARED"},
    })
    result = run_governed_execution(executor=_executor(aios, contract_id, permit_id, provider, Verifier()),
                                    store=JsonStateStore(store.path), policy=_policy(digest))
    assert result["status"] == "BLOCKED"
    assert "in-flight" in result["block_reason"]
    # The existing authority effect remains observed; no second provider invocation occurred.
    assert provider.calls == 1
    assert _effect_file(aios)["state"] == "OBSERVED_SUCCESS"
    reloaded = JsonStateStore(store.path).load()
    assert reloaded["status"] == "BLOCKED" and reloaded["terminal_evidence"]["status"] == "BLOCKED"
    # A later run stays terminal and still does not touch the provider.
    again = run_governed_execution(executor=_executor(aios, contract_id, permit_id, provider, Verifier()),
                                   store=JsonStateStore(store.path), policy=_policy(digest))
    assert again["status"] == "BLOCKED" and provider.calls == 1
    # And the generic loop reconciliation still cannot be pointed at it with this bridge's policy.
    with pytest.raises(ValueError, match="receipt-governed"):
        reconcile_in_flight_attempt(JsonStateStore(store.path), _policy(digest),
                                    {"effect_id": "x", "attempt_id": "y", "status": "OBSERVED",
                                     "evidence": {"e": 1}},
                                    authorizer=lambda intent, validated: None)


def test_supported_mode_persists_pass_across_a_fresh_store_with_sealed_effect_receipt(tmp_path):
    aios, contract_id, permit_id, digest = _authority(tmp_path / "authority")
    store = JsonStateStore(tmp_path / "loop-state.json")
    provider = Provider()
    result = run_governed_execution(executor=_executor(aios, contract_id, permit_id, provider, Verifier()),
                                    store=store, policy=_policy(digest))
    assert result["status"] == "PASS"
    reloaded = JsonStateStore(store.path).load()
    assert reloaded["status"] == "PASS" and "in_flight_attempt" not in reloaded
    effect = _effect_file(aios)
    assert effect["state"] == "OBSERVED_SUCCESS"
    assert reloaded["history"][-1]["action"]["effect_id"] == effect["effect_id"]
    assert load_receipt(aios, effect["receipt_id"])["outcome"] == "OBSERVED_SUCCESS"
    again = run_governed_execution(executor=_executor(aios, contract_id, permit_id, provider, Verifier()),
                                   store=JsonStateStore(store.path), policy=_policy(digest))
    assert again["status"] == "PASS" and provider.calls == 1    # terminal; never re-executed
