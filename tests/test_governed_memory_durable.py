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


def _record():
    return build_memory_record(
        memory_type="SEMANTIC",
        content={"topic": "durable memory", "fact": "WAL replay"},
        evidence_refs=[["EVIDENCE", "EV-1"]],
        predecessor="D-1",
        authority="AIOS_CONTROL_PLANE",
        source_commit="abc",
    ).as_dict()


def test_memory_write_requires_governed_mutation_and_lineage(tmp_path):
    store = WalStateStore(str(tmp_path / "state.json"))
    with pytest.raises(ValueError):
        persist_memory(store, _record(), decision_id="D-1", mutation_id="M-1", authority="NONE")
    persist_memory(store, _record(), decision_id="D-1", mutation_id="M-1", authority="AIOS_CONTROL_PLANE")
    assert load_memory(store)[0]["memory_id"] == _record()["memory_id"]


def test_unknown_execution_lineage_never_materializes(tmp_path):
    store = WalStateStore(str(tmp_path / "state.json"))
    with pytest.raises(ValueError, match="UNKNOWN"):
        persist_memory(
            store, _record(), decision_id="D-1", mutation_id="M-1",
            authority="AIOS_CONTROL_PLANE",
            execution_lineage={"effect_id": "E-1", "attempt_id": "A-1", "status": "UNKNOWN"},
        )


def test_memory_wal_tamper_fails_closed(tmp_path):
    store = WalStateStore(str(tmp_path / "state.json"))
    persist_memory(store, _record(), decision_id="D-1", mutation_id="M-1", authority="AIOS_CONTROL_PLANE")
    path = store.wal_path
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[-1])
    row["payload"]["value"]["memory"]["memory_id"] = "MEM-tampered"
    lines[-1] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(Exception):
        load_memory(store)


def test_memory_crash_after_wal_before_snapshot(tmp_path):
    state = tmp_path / "state.json"
    wal = tmp_path / "shared.wal.jsonl"
    memory = _record()
    script = (
        "import os\n"
        "from core.governed_memory import persist_memory\n"
        "from core.wal_state_store import WalStateStore\n"
        "class CrashStore(WalStateStore):\n"
        "    def _write_namespace_snapshot(self, namespace, value):\n"
        "        os._exit(137)\n"
        + "store = CrashStore(" + repr(str(state)) + ", " + repr(str(wal)) + ")\n"
        + "persist_memory(store, " + repr(memory) + ", decision_id='D-1', mutation_id='M-1', authority='AIOS_CONTROL_PLANE')\n"
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
