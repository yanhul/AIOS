import base64
import json

import pytest

from core.absorption_replay_store import LEDGER_REPOSITORY, ReplayStoreError, consume_permit_once


def _encoded_ledger(ledger):
    return base64.b64encode(json.dumps(ledger, separators=(",", ":")).encode()).decode()


def test_replay_store_creates_ledger_once_and_rejects_second_consumption(monkeypatch):
    state = {"ledger": None, "sha": None, "writes": 0}

    def fake_request(url, *, token, method="GET", payload=None):
        if method == "GET":
            if state["ledger"] is None:
                return 404, b""
            return 200, json.dumps({
                "sha": state["sha"], "content": _encoded_ledger(state["ledger"])
            }).encode()
        state["writes"] += 1
        state["ledger"] = json.loads(base64.b64decode(payload["content"]))
        state["sha"] = "blob-1"
        return 201, b"{}"

    monkeypatch.setattr("core.absorption_replay_store._api_request", fake_request)
    permit = {"signature": "signed", "target_apply_run_id": "123"}
    permit_id = consume_permit_once(permit=permit, repository=LEDGER_REPOSITORY, token="test", now=10)
    assert permit_id in state["ledger"]["consumed"]
    assert state["ledger"]["consumed"][permit_id] == {
        "consumed_at": 10, "target_apply_run_id": "123"
    }
    with pytest.raises(ReplayStoreError, match="already consumed"):
        consume_permit_once(permit=permit, repository="owner/repo", token="test", now=11)
    assert state["writes"] == 1


def test_replay_store_fails_closed_on_concurrent_compare_and_swap_conflict(monkeypatch):
    calls = []

    def fake_request(url, *, token, method="GET", payload=None):
        calls.append(method)
        if method == "GET":
            return 404, b""
        return 409, b"conflict"

    monkeypatch.setattr("core.absorption_replay_store._api_request", fake_request)
    with pytest.raises(ReplayStoreError, match="atomic replay-ledger write failed"):
        consume_permit_once(
            permit={"signature": "signed", "target_apply_run_id": "123"},
            repository="owner/repo", token="test",
        )
    assert calls == ["GET", "PUT"]


def test_replay_store_requires_write_token(monkeypatch):
    monkeypatch.delenv("AIOS_REPLAY_LEDGER_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "legacy-token-must-not-be-used")
    with pytest.raises(ReplayStoreError, match="AIOS_REPLAY_LEDGER_TOKEN"):
        consume_permit_once(
            permit={"signature": "signed", "target_apply_run_id": "123"},
            repository="owner/repo", token="",
        )


def test_replay_store_rejects_legacy_repository_or_branch(monkeypatch):
    monkeypatch.setenv("AIOS_REPLAY_LEDGER_TOKEN", "test")
    permit = {"signature": "signed", "target_apply_run_id": "123"}
    with pytest.raises(ReplayStoreError, match="dedicated AIOS-replay-ledger"):
        consume_permit_once(permit=permit, repository="yanhul/AIOS")
    with pytest.raises(ReplayStoreError, match="branch must be main"):
        consume_permit_once(permit=permit, repository=LEDGER_REPOSITORY,
                            branch="aios-absorption-replay-ledger")
