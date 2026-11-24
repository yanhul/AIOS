# AIOS-CONTRACT: TRY provider client must fail closed on missing config and invalid/untrusted responses.
# AIOS-REGRESSION: Canonical Worker URL/token names must work without legacy configuration aliases.
# AIOS-OWNER: core.try_repair_provider public health/propose boundary.
# AIOS-COVERAGE-GAP: Live Worker/Gemini and GitHub secret availability are not covered by unit tests.
# AIOS-BASELINE: Existing schema-2 proposal, HOLD, identity, path-safety, and retry contracts remain enforced.
import json
import hashlib
import hmac
import time

import pytest

from core import try_repair_provider
from core.try_operation_receipt import TryOperationReceiptKeyring, SIGNED_FIELDS


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


def _operation_keyring(monkeypatch):
    secret = "try-operation-secret-for-tests-0123456789"
    spec = {"try.repair": {"key_id": "try-op-test-v1", "secret": secret,
                           "scopes": ["try.operation.receipt.verify"], "revoked": False}}
    monkeypatch.setenv("AIOS_TRY_OPERATION_KEYRING", json.dumps(spec))
    return TryOperationReceiptKeyring(spec), secret


def _signed_operation_receipt(*, secret, status="COMPLETED", request_digest, repository="yanhul/AIOS",
                              sha="a" * 40, attempt=1, proposal=None):
    proposal = proposal or {"schema": 2, "files": [{"path": "core/x.py", "content": "x=2"}]}
    body = {
        "type": "TRY_PROPOSAL_OPERATION_RECEIPT_V1", "issuer": "try.repair",
        "key_id": "try-op-test-v1", "receipt_id": "TR-" + "a" * 32,
        "request_id": "req-1", "request_digest": request_digest,
        "repository": repository, "sha": sha, "attempt": attempt,
        "status": status,
        "execution_state": "COMPLETED" if status == "COMPLETED" else (
            "NOT_SUBMITTED" if status == "FAILED" else "IN_PROGRESS_OR_AMBIGUOUS"),
        "failure_code": "provider_not_configured" if status == "FAILED" else None,
        "proposal_digest": hashlib.sha256(json.dumps(
            proposal, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()).hexdigest() if status == "COMPLETED" else None,
        "issued_at": time.time(), "expires_at": time.time() + 300, "algorithm": "HMAC-SHA256",
    }
    signed = {key: body[key] for key in SIGNED_FIELDS}
    body["signature"] = hmac.new(secret.encode(), json.dumps(
        signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode(), hashlib.sha256).hexdigest()
    return body


def test_lookup_proposal_returns_digest_bound_completed_result(monkeypatch):
    proposal = {"schema": 2, "files": [{"path": "core/x.py", "content": "x=2"}]}
    body = _provider_body()
    digest = try_repair_provider._request_digest(body)
    _keyring, secret = _operation_keyring(monkeypatch)
    receipt = _signed_operation_receipt(secret=secret, request_digest=digest, proposal=proposal)
    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({"status": "COMPLETED", "request_id": "req-1",
                               "request_digest": digest, "proposal": proposal,
                               "operation_receipt": receipt}).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    result = try_repair_provider.lookup_proposal(
        request_id="req-1", expected_request_digest=digest, expected_repository="yanhul/AIOS",
        expected_sha="a" * 40, expected_attempt=1,
    )
    assert result["status"] == "COMPLETED"
    assert result["proposal"]["files"][0]["path"] == "core/x.py"


def test_lookup_proposal_unknown_is_never_retry_permission(monkeypatch):
    body = _provider_body()
    digest = try_repair_provider._request_digest(body)
    _keyring, secret = _operation_keyring(monkeypatch)
    receipt = _signed_operation_receipt(secret=secret, status="UNKNOWN", request_digest=digest)
    class Resp:
        status = 202
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({"status": "UNKNOWN", "execution_state": "IN_PROGRESS_OR_AMBIGUOUS",
                               "request_id": "req-1", "request_digest": digest,
                               "retry_allowed": False, "operation_receipt": receipt}).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    result = try_repair_provider.lookup_proposal(
        request_id="req-1", expected_request_digest=digest, expected_repository="yanhul/AIOS",
        expected_sha="a" * 40, expected_attempt=1,
    )
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
        try_repair_provider.lookup_proposal(
            request_id="req-1", expected_request_digest="a" * 64,
            expected_repository="yanhul/AIOS", expected_sha="a" * 40, expected_attempt=1,
        )


def test_propose_recovers_cached_result_after_503_without_repeating_gemini(monkeypatch):
    import urllib.error
    body = _provider_body()
    digest = try_repair_provider._request_digest(body)
    _keyring, secret = _operation_keyring(monkeypatch)
    proposal = {"schema": 2, "files": [{"path": "core/x.py", "content": "x=2"}]}
    receipt = _signed_operation_receipt(secret=secret, request_digest=digest, proposal=proposal)
    calls = []
    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "status": "COMPLETED", "request_id": "req-1", "request_digest": digest,
                "proposal": proposal, "operation_receipt": receipt,
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
    _keyring, secret = _operation_keyring(monkeypatch)
    receipt = _signed_operation_receipt(secret=secret, status="UNKNOWN", request_digest=digest)
    calls = []
    class Resp:
        status = 202
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({
                "status": "UNKNOWN", "execution_state": "IN_PROGRESS_OR_AMBIGUOUS",
                "request_id": "req-1", "request_digest": digest, "retry_allowed": False,
                "operation_receipt": receipt,
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
    assert try_repair_provider.lookup_proposal(
        request_id="req-1", expected_request_digest="a" * 64,
        expected_repository="yanhul/AIOS", expected_sha="a" * 40, expected_attempt=1,
    ) is None
    def old_worker(*a, **k):
        raise urllib.error.HTTPError("u", 404, "missing", {}, io.BytesIO(b'{"error":"not_found"}'))
    monkeypatch.setattr(try_repair_provider, "_open", old_worker)
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="endpoint unavailable"):
        try_repair_provider.lookup_proposal(
            request_id="req-1", expected_request_digest="a" * 64,
            expected_repository="yanhul/AIOS", expected_sha="a" * 40, expected_attempt=1,
        )


def test_propose_persists_aios_operation_binding_before_post(monkeypatch):
    events = []
    class Resp:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({"schema": 2, "files": [{"path": "core/x.py", "content": "x=2"}]}).encode()
    def bind(*args, **kwargs):
        events.append(("bind", kwargs["request_id"], kwargs["request_digest"]))
    def post(req, timeout):
        events.append(("post", req.get_method()))
        return Resp()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "bind_try_operation_request", bind)
    monkeypatch.setattr(try_repair_provider, "_open", post)
    result = try_repair_provider.propose(
        request_id="EF-1:attempt:1", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
        failure={}, source={"core/x.py": "x=1\n"},
        aios_dir="/tmp/aios", effect_id="EF-1", actor="agent:test",
    )
    assert result["request_id"] == "EF-1:attempt:1"
    assert events[0][0] == "bind"
    assert events[0][2] == try_repair_provider._request_digest({
        "request_id": "EF-1:attempt:1", "repository": "yanhul/AIOS", "sha": "a" * 40,
        "attempt": 1, "failure": {}, "source_snapshot": {"core/x.py": "x=1\n"},
    })
    assert events[1] == ("post", "POST")


def test_propose_never_posts_when_aios_operation_binding_fails(monkeypatch):
    calls = []
    def fail(*args, **kwargs):
        raise RuntimeError("effect is not dispatched")
    def post(*args, **kwargs):
        calls.append(1)
        raise AssertionError("provider must not be called after binding failure")
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "bind_try_operation_request", fail)
    monkeypatch.setattr(try_repair_provider, "_open", post)
    with pytest.raises(try_repair_provider.TryRepairProviderError, match="before provider submission"):
        try_repair_provider.propose(
            request_id="EF-1:attempt:1", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
            failure={}, source={"core/x.py": "x=1\n"},
            aios_dir="/tmp/aios", effect_id="EF-1", actor="agent:test",
        )
    assert calls == []


def test_lookup_failed_not_submitted_receipt_is_reconciliation_input_not_auto_retry(monkeypatch):
    body = _provider_body()
    digest = try_repair_provider._request_digest(body)
    _keyring, secret = _operation_keyring(monkeypatch)
    receipt = _signed_operation_receipt(secret=secret, status="FAILED", request_digest=digest)
    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({"status": "FAILED", "request_id": "req-1", "request_digest": digest,
                               "failure_code": "provider_not_configured", "execution_state": "NOT_SUBMITTED",
                               "retry_allowed": False, "operation_receipt": receipt}).encode()
    monkeypatch.setenv("TRY_REPAIR_WORKER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider, "_open", lambda *a, **k: Resp())
    result = try_repair_provider.lookup_proposal(
        request_id="req-1", expected_request_digest=digest, expected_repository="yanhul/AIOS",
        expected_sha="a" * 40, expected_attempt=1,
    )
    assert result["status"] == "FAILED"
    assert result["proven_not_submitted"] is True
    assert result["retry_allowed"] is False
