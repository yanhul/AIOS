import hashlib
import io
import json
import zipfile

import pytest

from core import try_repair_relay


def _archive(proposal):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("repair-proposal.json", json.dumps(proposal))
    return buf.getvalue()


def test_relay_requires_token(monkeypatch):
    monkeypatch.delenv("TRY_GITHUB_TOKEN", raising=False)
    with pytest.raises(try_repair_relay.TryRelayError, match="TRY_GITHUB_TOKEN"):
        try_repair_relay.propose(
            request_id="r", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
            failure={}, source={"core/x.py": "x=1"},
        )


def test_relay_verifies_run_artifact_identity(monkeypatch):
    proposal = {
        "schema": 2,
        "root_cause": "x",
        "proposed_fix": "y",
        "files": [{"path": "core/x.py", "content": "x=1"}],
        "request_id": "r",
        "base_sha": "a" * 40,
        "attempt": 1,
    }
    archive = _archive(proposal)
    digest = "sha256:" + hashlib.sha256(archive).hexdigest()
    calls = []

    def fake_request(method, path, token, body=None):
        calls.append((method, path, body))
        if method == "POST":
            return {"workflow_run_id": 42}
        if path.endswith("/actions/runs/42"):
            return {"status": "completed", "conclusion": "success"}
        return {"artifacts": [{
            "id": 9,
            "name": "aios-repair-r",
            "expired": False,
            "digest": digest,
        }]}

    monkeypatch.setenv("TRY_GITHUB_TOKEN", "token")
    monkeypatch.setattr(try_repair_relay, "_request", fake_request)
    monkeypatch.setattr(try_repair_relay, "_download", lambda path, token: archive)
    out = try_repair_relay.propose(
        request_id="r", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
        failure={}, source={"core/x.py": "x=1"},
    )
    assert out["request_id"] == "r"
    assert out["base_sha"] == "a" * 40
    assert any(c[0] == "POST" for c in calls)


def test_relay_rejects_digest_mismatch(monkeypatch):
    proposal = {
        "schema": 2, "root_cause": "x", "proposed_fix": "y",
        "files": [{"path": "core/x.py", "content": "x=1"}],
        "request_id": "r", "base_sha": "a" * 40, "attempt": 1,
    }
    archive = _archive(proposal)

    def fake_request(method, path, token, body=None):
        if method == "POST":
            return {"workflow_run_id": 42}
        if path.endswith("/actions/runs/42"):
            return {"status": "completed", "conclusion": "success"}
        return {"artifacts": [{
            "id": 9, "name": "aios-repair-r", "expired": False,
            "digest": "sha256:" + "0" * 64,
        }]}

    monkeypatch.setenv("TRY_GITHUB_TOKEN", "token")
    monkeypatch.setattr(try_repair_relay, "_request", fake_request)
    monkeypatch.setattr(try_repair_relay, "_download", lambda path, token: archive)
    with pytest.raises(try_repair_relay.TryRelayError, match="digest mismatch"):
        try_repair_relay.propose(
            request_id="r", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
            failure={}, source={"core/x.py": "x=1"},
        )
