import json
import os
import subprocess
import sys

import pytest

# AIOS-CONTRACT: Memory writes must replay from durable WAL without trusting snapshots
# AIOS-REGRESSION: Prevent memory history loss, UNKNOWN promotion, and WAL tampering
# AIOS-OWNER: AIOS control-plane governed memory and durable persistence
# AIOS-COVERAGE-GAP: Exercises memory namespace recovery and crash-after-WAL boundary
# AIOS-BASELINE: Regression coverage for shared WAL state/memory store

from core.governed_memory import build_memory_record, load_memory, persist_memory, retrieve_memory
from core.wal_state_store import WalStateStore
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.policy_registry import persist_policy


def _record():
    return build_memory_record(
        memory_type="SEMANTIC",
        content={"topic": "durable memory", "fact": "WAL replay"},
        evidence_refs=[["EVIDENCE", "EV-1"]],
        predecessor="D-1",
        authority="AIOS_CONTROL_PLANE",
        source_commit="abc",
    ).as_dict()


def _authorization(aios_dir):
    policy = {"policy_type": "GOVERNING_POLICY", "rules": ["MEMORY_WRITE"]}
    digest = persist_policy(aios_dir, policy)
    registry = CapabilityRegistry()
    registry.register(Capability(
        capability_id="memory.write", version="1", owner="AIOS", kind="memory",
        permissions=("MEMORY_WRITE",), status="ACTIVE",
    ))
    registry.persist(aios_dir, actor="test-setup")
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "memory-test",
        "scope": "memory:write", "actor": "test-writer",
        "capabilities": ["memory.write@1"], "input_digest": "test-input",
        "allowed_effects": ["MEMORY_WRITE"], "evidence_required": ["EVIDENCE"],
        "max_attempts": 1, "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": digest,
    }
    stored = persist_contract(aios_dir, contract)
    permit = persist_permit(aios_dir, stored, issuer="test-issuer")
    return {"aios_dir": aios_dir, "contract_id": stored["contract_id"],
            "permit_id": permit["permit_id"], "actor": "test-writer"}


def test_memory_write_requires_governed_mutation_and_lineage(tmp_path):
    auth = _authorization(str(tmp_path / "aios"))
    store = WalStateStore(str(tmp_path / "state.json"))
    with pytest.raises(ValueError):
        persist_memory(store, _record(), decision_id="D-1", mutation_id="M-1", authority="NONE", **auth)
    persist_memory(store, _record(), decision_id="D-1", mutation_id="M-1", authority="AIOS_CONTROL_PLANE", **auth)
    second = build_memory_record(
        memory_type="EPISODIC",
        content={"topic": "durable memory", "fact": "second write"},
        evidence_refs=[["EVIDENCE", "EV-2"]],
        predecessor="D-2",
        authority="AIOS_CONTROL_PLANE",
        source_commit="def",
    ).as_dict()
    persist_memory(store, second, decision_id="D-2", mutation_id="M-2", authority="AIOS_CONTROL_PLANE", **auth)
    loaded = load_memory(store)
    assert [item["memory_id"] for item in loaded] == [_record()["memory_id"], second["memory_id"]]


def test_unknown_execution_lineage_never_materializes(tmp_path):
    auth = _authorization(str(tmp_path / "aios"))
    store = WalStateStore(str(tmp_path / "state.json"))
    with pytest.raises(ValueError, match="UNKNOWN"):
        persist_memory(
            store, _record(), decision_id="D-1", mutation_id="M-1",
            authority="AIOS_CONTROL_PLANE",
            execution_lineage={"effect_id": "E-1", "attempt_id": "A-1", "status": "UNKNOWN"}, **auth,
        )


def test_memory_wal_tamper_fails_closed(tmp_path):
    auth = _authorization(str(tmp_path / "aios"))
    store = WalStateStore(str(tmp_path / "state.json"))
    persist_memory(store, _record(), decision_id="D-1", mutation_id="M-1", authority="AIOS_CONTROL_PLANE", **auth)
    path = store.wal_path
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[-1])
    row["payload"]["item"]["memory"]["memory_id"] = "MEM-tampered"
    lines[-1] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(Exception):
        load_memory(store)


def test_memory_crash_after_wal_before_snapshot(tmp_path):
    state = tmp_path / "state.json"
    wal = tmp_path / "shared.wal.jsonl"
    memory = _record()
    auth = _authorization(str(tmp_path / "aios"))
    script = (
        "import os\n"
        "from core.governed_memory import persist_memory\n"
        "from core.wal_state_store import WalStateStore\n"
        "auth = " + repr(auth) + "\n"
        "class CrashStore(WalStateStore):\n"
        "    def _write_namespace_snapshot(self, namespace, value):\n"
        "        os._exit(137)\n"
        + "store = CrashStore(" + repr(str(state)) + ", " + repr(str(wal)) + ")\n"
        + "persist_memory(store, " + repr(memory) + ", decision_id='D-1', mutation_id='M-1', authority='AIOS_CONTROL_PLANE', **auth)\n"
    )
    proc = subprocess.run([sys.executable, "-c", script], cwd=os.getcwd())
    assert proc.returncode == 137
    assert not (tmp_path / "state.memory.json").exists()
    recovered = load_memory(WalStateStore(str(state), str(wal)))
    assert recovered == [memory]


def test_prior_commit_remains_candidate_with_governed_evidence_boundary():
    item = _record()
    found = retrieve_memory(
        [item],
        query="durable",
        current_commit="new",
        evidence_resolver=lambda refs: ([{"entity_id": "EV-1"}], []),
    )
    assert found and found[0]["source_commit"] == "abc"
    assert found[0]["authority"] == "NONE"
