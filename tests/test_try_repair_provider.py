# AIOS-CONTRACT: TRY provider client must fail closed on missing config and invalid/untrusted responses.
# AIOS-REGRESSION: Canonical Worker URL/token names must work without legacy configuration aliases.
# AIOS-OWNER: core.try_repair_provider public health/propose boundary.
# AIOS-COVERAGE-GAP: Live Worker/Gemini and GitHub secret availability are not covered by unit tests.
# AIOS-BASELINE: Existing schema-2 proposal, HOLD, identity, path-safety, and retry contracts remain enforced.
import json

import pytest

from core import try_repair_provider


def test_provider_requires_try_url(monkeypatch):
    monkeypatch.delenv("TRY_REPAIR_WORKER_URL", raising=False)
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    with pytest.raises(try_repair_provider.TryRepairProviderError):
        try_repair_provider.propose(
            request_id="r", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
            failure={}, source={"core/x.py": "x=1\n"},
        )


def test_provider_rejects_malformed_response(monkeypatch):
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self): return json.dumps({"schema": 1}).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="invalid proposal schema"):
        try_repair_provider.propose(
            request_id="r", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
            failure={}, source={"core/x.py": "x=1\n"},
        )


def test_provider_accepts_hold(monkeypatch):
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self): return json.dumps({"status": "HOLD", "reason": "no safe fix"}).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    out = try_repair_provider.propose(
        request_id="r", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
        failure={}, source={"core/x.py": "x=1\n"},
    )
    assert out["status"] == "HOLD"


def test_health_rejects_missing_endpoint(monkeypatch):
    monkeypatch.delenv("TRY_REPAIR_WORKER_URL", raising=False)
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    with pytest.raises(try_repair_provider.TryRepairProviderError):
        try_repair_provider.health()


def test_health_accepts_ready(monkeypatch):
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self): return b'{"status":"READY","provider":"gemini","model":"test-model"}'
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    assert try_repair_provider.health()["status"] == "READY"


def test_provider_rejects_protected_patch_path(monkeypatch):
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "schema": 2, "root_cause": "x", "proposed_fix": "y",
                "files": [{"path": ".aios/policy.py", "content": "x"}],
            }).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="protected patch path"):
        try_repair_provider.propose(
            request_id="r", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
            failure={}, source={"core/x.py": "x=1\n"},
        )


def test_provider_adds_repair_identity(monkeypatch):
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "schema": 2, "root_cause": "x", "proposed_fix": "y",
                "files": [{"path": "core/x.py", "content": "x=1\n"}],
            }).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    out = try_repair_provider.propose(
        request_id="req-1", repository="yanhul/AIOS", sha="a" * 40, attempt=2,
        failure={}, source={"core/x.py": "x=1\n"},
    )
    assert out["request_id"] == "req-1"
    assert out["base_sha"] == "a" * 40
    assert out["attempt"] == 2


def test_provider_does_not_retry_quota_429(monkeypatch):
    import urllib.error
    calls = []
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    def fail(*a, **k):
        calls.append(1)
        raise urllib.error.HTTPError("u", 429, "quota", {}, None)
    monkeypatch.setattr(try_repair_provider, "_open", fail)
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="HTTP 429"):
        try_repair_provider.propose(request_id="r", repository="yanhul/AIOS", sha="a"*40, attempt=1, failure={}, source={"core/x.py":"x=1\n"})
    assert len(calls) == 1

def test_provider_rejects_ambiguous_patch_paths(monkeypatch):
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "schema": 2, "root_cause": "x", "proposed_fix": "y",
                "files": [{"path": "core//x.py", "content": "x=1\n"}],
            }).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="ambiguous patch path"):
        try_repair_provider.propose(
            request_id="r", repository="yanhul/AIOS", sha="a"*40, attempt=1,
            failure={}, source={"core/x.py": "x=1\n"},
        )


def test_provider_rejects_duplicate_normalized_patch_paths(monkeypatch):
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "schema": 2, "root_cause": "x", "proposed_fix": "y",
                "files": [
                    {"path": "core/x.py", "content": "a"},
                    {"path": r"core\x.py", "content": "b"},
                ],
            }).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="duplicate patch path"):
        try_repair_provider.propose(
            request_id="r", repository="yanhul/AIOS", sha="a"*40, attempt=1,
            failure={}, source={"core/x.py": "x=1\n"},
        )


def test_provider_rejects_nested_protected_patch_path(monkeypatch):
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "schema": 2, "root_cause": "x", "proposed_fix": "y",
                "files": [{"path": "vendor/.git/config", "content": "x"}],
            }).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="protected patch path"):
        try_repair_provider.propose(
            request_id="r", repository="yanhul/AIOS", sha="a"*40, attempt=1,
            failure={}, source={"core/x.py": "x=1\n"},
        )


def _provider_body():
    return {
        "request_id": "req-1", "repository": "yanhul/AIOS", "sha": "a" * 40,
        "attempt": 1, "failure": {}, "source_snapshot": {"core/x.py": "x=1\n"},
    }


def test_lookup_proposal_returns_digest_bound_completed_result(monkeypatch):
    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "status": "COMPLETED", "request_id": "req-1",
                "request_digest": "a" * 64,
                "proposal": {"schema": 2, "files": [{"path": "core/x.py", "content": "x=2"}]},
            }).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    result = try_repair_provider.lookup_proposal(request_id="req-1", expected_request_digest="a" * 64)
    assert result["status"] == "COMPLETED"
    assert result["proposal"]["files"][0]["path"] == "core/x.py"


def test_lookup_proposal_unknown_is_never_retry_permission(monkeypatch):
    class Resp:
        status = 202
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "status": "UNKNOWN", "execution_state": "IN_PROGRESS",
                "request_id": "req-1", "request_digest": "a" * 64,
                "retry_allowed": False,
            }).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    result = try_repair_provider.lookup_proposal(request_id="req-1", expected_request_digest="a" * 64)
    assert result["status"] == "UNKNOWN"
    assert result["retry_allowed"] is False


def test_lookup_proposal_rejects_request_digest_mismatch(monkeypatch):
    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "status": "COMPLETED", "request_id": "req-1",
                "request_digest": "b" * 64,
                "proposal": {"schema": 2, "files": [{"path": "core/x.py", "content": "x=2"}]},
            }).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="digest mismatch"):
        try_repair_provider.lookup_proposal(request_id="req-1", expected_request_digest="a" * 64)


def test_propose_recovers_cached_result_after_503_without_repeating_gemini(monkeypatch):
    import urllib.error
    body = _provider_body()
    digest = try_repair_provider._request_digest(body)
    calls = []
    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "status": "COMPLETED", "request_id": "req-1", "request_digest": digest,
                "proposal": {"schema": 2, "files": [{"path": "core/x.py", "content": "x=2"}]},
            }).encode()
    def fake_open(req, timeout):
        calls.append(req.get_method())
        if req.get_method() == "POST":
            raise urllib.error.HTTPError("u", 503, "upstream", {}, None)
        return Resp()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", fake_open)
    result = try_repair_provider.propose(
        request_id="req-1", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
        failure={}, source={"core/x.py": "x=1\n"},
    )
    assert result["files"][0]["content"] == "x=2"
    assert calls == ["POST", "GET"]


def test_propose_does_not_retry_unknown_operation_after_503(monkeypatch):
    import urllib.error
    body = _provider_body()
    digest = try_repair_provider._request_digest(body)
    calls = []
    class Resp:
        status = 202
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "status": "UNKNOWN", "execution_state": "IN_PROGRESS",
                "request_id": "req-1", "request_digest": digest, "retry_allowed": False,
            }).encode()
    def fake_open(req, timeout):
        calls.append(req.get_method())
        if req.get_method() == "POST":
            raise urllib.error.HTTPError("u", 503, "upstream", {}, None)
        return Resp()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", fake_open)
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="operation UNKNOWN"):
        try_repair_provider.propose(
            request_id="req-1", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
            failure={}, source={"core/x.py": "x=1\n"},
        )
    assert calls == ["POST", "GET"]



def test_lookup_missing_operation_is_distinct_from_unsupported_old_worker(monkeypatch):
    import io
    import urllib.error
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    def missing(*a, **k):
        raise urllib.error.HTTPError("u", 404, "missing", {}, io.BytesIO(b'{"error":"proposal_operation_not_found"}'))
    monkeypatch.setattr(try_repair_provider, "_open", missing)
    assert try_repair_provider.lookup_proposal(request_id="req-1") is None
    def old_worker(*a, **k):
        raise urllib.error.HTTPError("u", 404, "missing", {}, io.BytesIO(b'{"error":"not_found"}'))
    monkeypatch.setattr(try_repair_provider, "_open", old_worker)
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="endpoint unavailable"):
        try_repair_provider.lookup_proposal(request_id="req-1")
