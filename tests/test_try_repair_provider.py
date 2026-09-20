import json

import pytest

from core import try_repair_provider


def test_provider_requires_try_url(monkeypatch):
    monkeypatch.delenv("TRY_REPAIR_PROVIDER_URL", raising=False)
    monkeypatch.setenv("TRY_REPAIR_PROVIDER_TOKEN", "x")
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
    monkeypatch.setenv("TRY_REPAIR_PROVIDER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_REPAIR_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider.urllib.request, "urlopen", lambda *a, **k: Resp())
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
    monkeypatch.setenv("TRY_REPAIR_PROVIDER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("TRY_REPAIR_PROVIDER_TOKEN", "x")
    monkeypatch.setattr(try_repair_provider.urllib.request, "urlopen", lambda *a, **k: Resp())
    out = try_repair_provider.propose(
        request_id="r", repository="yanhul/AIOS", sha="a" * 40, attempt=1,
        failure={}, source={"core/x.py": "x=1\n"},
    )
    assert out["status"] == "HOLD"
