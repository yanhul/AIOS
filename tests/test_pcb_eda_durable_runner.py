# AIOS-CONTRACT: EDA runner state is WAL-backed and bound to exact design/source/input/config/kit revision.
# AIOS-REGRESSION: Refuse stale or tampered continuation and recover state from WAL over stale snapshot.
# AIOS-OWNER: AIOS durable PCB EDA runner.
# AIOS-COVERAGE-GAP: Exercise the production runner's store and workload identity boundary.
# AIOS-BASELINE: Validate fail-closed durable EDA continuation.

import json

import pytest

from core.wal_state_store import WalStateStore
from scripts.run_pcb_eda_schematic_durable import validate_resume_identity


def identity():
    return {
        "design": "QI9-2605-A01",
        "source_commit": "a" * 40,
        "input_sha256": "b" * 64,
        "config_sha256": "c" * 64,
        "kit_commit": "d" * 40,
    }


def state(workload_identity=None):
    expected = identity() if workload_identity is None else workload_identity
    return {
        "project": "yanhul/temp",
        "design": expected["design"],
        "active_commit": expected["source_commit"],
        "workload_identity": dict(expected),
    }


def test_runner_store_recovers_committed_state_when_snapshot_is_stale(tmp_path):
    snapshot = tmp_path / "state.json"
    store = WalStateStore(str(snapshot))
    committed = state()
    committed["step"] = 7
    store.save(committed)

    # Simulate an old snapshot surviving after the WAL commit.
    snapshot.write_text(json.dumps({"step": 0}), encoding="utf-8")
    recovered = store.load()

    assert recovered["step"] == 7
    assert recovered["workload_identity"] == identity()
    assert snapshot.with_suffix(".json.wal.jsonl").is_file()


def test_resume_requires_exact_persisted_workload_identity():
    validate_resume_identity(state(), identity())

    changed = identity()
    changed["input_sha256"] = "e" * 64
    with pytest.raises(ValueError, match="identity mismatch"):
        validate_resume_identity(state(), changed)


def test_resume_blocks_legacy_state_without_identity():
    legacy = {"design": "QI9-2605-A01", "active_commit": "a" * 40}
    with pytest.raises(ValueError, match="lacks workload_identity"):
        validate_resume_identity(legacy, identity())


def test_resume_blocks_design_or_source_commit_drift_even_if_identity_matches():
    item = state()
    item["active_commit"] = "f" * 40
    with pytest.raises(ValueError, match="design/source commit"):
        validate_resume_identity(item, identity())
