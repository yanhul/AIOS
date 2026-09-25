"""Mutation proofs for load-bearing AIOS invariants.

These tests deliberately mutate production owners in an isolated copy and
require the corresponding keeper invariant to fail. A mutation that survives
is a test-suite hole, not a production failure.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


# AIOS-CONTRACT: load-bearing security/lineage invariants must be protected by keeper tests that kill owner mutations
# AIOS-REGRESSION: retry identity or receipt gating could regress while ordinary happy-path tests remain green
# AIOS-OWNER: core/effect_authority.py and core/durable_loop.py
# AIOS-COVERAGE-GAP: ordinary green tests do not prove that deliberately removed guards make the keeper red
# AIOS-BASELINE: each isolated mutation must make its focused invariant harness exit nonzero


ROOT = Path(__file__).resolve().parents[1]


def _run_mutant(source_path: str, mutation: tuple[str, str], harness: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as td:
        sandbox = Path(td)
        shutil.copytree(ROOT / "core", sandbox / "core")
        target = sandbox / source_path
        source = target.read_text(encoding="utf-8")
        old, new = mutation
        assert source.count(old) == 1, f"mutation anchor drifted for {source_path}"
        target.write_text(source.replace(old, new), encoding="utf-8")

        harness_path = sandbox / "keeper.py"
        harness_path.write_text(harness, encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONPATH"] = str(sandbox)
        return subprocess.run(
            [sys.executable, str(harness_path)],
            cwd=sandbox,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )


def test_retry_attempt_identity_mutation_is_killed():
    mutation = (
        '    if attempt_id != _attempt_id(effect_id, attempt):\n'
        '        raise ValueError("attempt_id does not match retry attempt")\n',
        "",
    )
    harness = r'''
import tempfile
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch, retry_dispatch, unknown
from core.policy_registry import persist_policy

with tempfile.TemporaryDirectory() as td:
    registry = CapabilityRegistry()
    registry.register(Capability("provider-1", "1", "test-fixture", "external_effect", status="ACTIVE"))
    registry.persist(td, "test-fixture")
    policy = persist_policy(td, {"policy_type": "GOVERNING_POLICY", "name": "mutation"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "mutation-retry",
        "scope": "test",
        "actor": "agent-1",
        "capabilities": ["provider-1@1"],
        "input_digest": "input",
        "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"],
        "max_attempts": 2,
        "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE", "UNKNOWN"],
        "policy_digest": policy,
    }
    persist_contract(td, contract)
    permit = persist_permit(td, contract, "agent-1")
    effect = create_effect(td, contract_identity(contract), "op-1", "agent-1", permit["permit_id"], "external_effect")
    dispatch(td, effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(td, effect["effect_id"], "agent-1", "timeout")

    # This must fail against the real owner. The mutant removes that fence.
    try:
        retry_dispatch(
            td, effect["effect_id"], "agent-1",
            "FORGED-ATTEMPT-ID", "provider-1", 2
        )
    except (ValueError, RuntimeError):
        raise AssertionError("mutation was unexpectedly killed before the retry identity fence")
    else:
        raise AssertionError("keeper invariant: forged retry attempt was accepted")
'''
    result = _run_mutant("core/effect_authority.py", mutation, harness)
    assert result.returncode != 0, result.stdout + result.stderr


def test_execution_receipt_gate_mutation_is_killed():
    mutation = (
        '            if policy.require_execution_receipt:\n'
        '                receipt = _validate_execution_receipt(verification)\n',
        '            if False:\n'
        '                receipt = _validate_execution_receipt(verification)\n',
    )
    harness = r'''
from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop

class Executor:
    def observe(self, state):
        return {"n": state["step"]}
    def decide(self, observation, state):
        return {"next": observation["n"] + 1}
    def act(self, decision, state):
        return decision["next"]
    def verify(self, action_result, state):
        return {"value": action_result}

policy = LoopPolicy(
    max_steps=1,
    terminal_evaluator=lambda verification, state: "PASS",
    action_authorizer=lambda decision, state: None,
    require_execution_receipt=True,
)
result = run_durable_loop(Executor(), MemoryStateStore(), policy)

# The real owner must block before terminal evaluation. The mutant skips
# receipt validation and therefore incorrectly reaches PASS.
if result["status"] == "PASS":
    raise AssertionError("keeper invariant: missing execution receipt reached PASS")
if result["status"] != "BLOCKED":
    raise AssertionError(f"keeper invariant: expected BLOCKED, got {result['status']!r}")
'''
    result = _run_mutant("core/durable_loop.py", mutation, harness)
    assert result.returncode != 0, result.stdout + result.stderr
