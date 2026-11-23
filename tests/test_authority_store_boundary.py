from pathlib import Path

import pytest

from core.authority_store import FileAuthorityStore


def test_file_authority_store_commits_record_batch_atomically(tmp_path):
    store = FileAuthorityStore(str(tmp_path))
    committed = store.commit([
        ("authority/contracts/C-1.json", {"contract_id": "C-1"}),
        ("events/contract-C-1.json", {"kind": "contract", "id": "C-1"}),
    ])
    assert len(committed) == 2
    assert (tmp_path / "authority/contracts/C-1.json").exists()
    assert (tmp_path / "events/contract-C-1.json").exists()


def test_file_authority_store_precondition_failure_writes_nothing(tmp_path):
    store = FileAuthorityStore(str(tmp_path))

    def reject(_root):
        raise RuntimeError("stale snapshot")

    with pytest.raises(RuntimeError, match="stale snapshot"):
        store.commit([("effects/EF-1.json", {"state": "DISPATCHED"})],
                     precondition=reject)
    assert not (tmp_path / "effects/EF-1.json").exists()


def test_file_authority_store_rejects_empty_batch(tmp_path):
    store = FileAuthorityStore(str(tmp_path))
    with pytest.raises(ValueError, match="non-empty"):
        store.commit([])
