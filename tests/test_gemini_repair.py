import json
from unittest.mock import patch
from core.gemini_repair import GeminiRepairProvider

def test_gemini_provider_is_proposal_only():
    provider = GeminiRepairProvider(api_key="test", model="gemini-test")
    payload = {"candidates":[{"content":{"parts":[{"text":json.dumps({
        "root_cause":"bad API binding","proposed_fix":"bind permit",
        "files":[{"path":"core/x.py","content":"x=1"}],
        "regression_tests":["test_binding"],"confidence":0.8})}]}}]}
    class Response:
        def __enter__(self): return self
        def __exit__(self,*args): return False
        def read(self): return json.dumps(payload).encode()
    with patch("urllib.request.urlopen", return_value=Response()):
        result=provider.propose(failure={"status":"FAIL","evidence_refs":["EV-1"]},
                                repository_snapshot="snapshot")
    assert result.root_cause=="bad API binding"
    assert result.files[0]["path"]=="core/x.py"
    assert result.regression_tests==("test_binding",)

def test_gemini_requires_key():
    try:
        GeminiRepairProvider(api_key="")
    except RuntimeError as exc:
        assert "GEMINI_API_KEY" in str(exc)
    else:
        raise AssertionError("missing key was accepted")
