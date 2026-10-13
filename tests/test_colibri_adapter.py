# AIOS-CONTRACT: One authorized, bounded inference request yields a receipt bound to its effect and attempt.
# AIOS-REGRESSION: Prevent unauthorized capability use, malformed provider output, and unbounded I/O.
# AIOS-OWNER: AIOS capability/runtime boundary; Colibri remains an external inference provider.
# AIOS-COVERAGE-GAP: Hermetic fake-server tests do not prove a real model/server integration.
# AIOS-BASELINE: Colibri source revision bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850; adapter contract v1.
"""Conformance tests for the governed Colibri adapter; no model download required."""
import json

import pytest

from adapters.colibri.runner import COLIBRI_CAPABILITY, ColibriAdapter


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit=-1):
        return self.body if limit < 0 else self.body[:limit]


def response(body=None):
    body = body or {
        "id": "chatcmpl-test-1",
        "model": "test-model",
        "choices": [{"message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
    }
    return FakeResponse(json.dumps(body).encode())


def authorized_contract(**overrides):
    value = {"task_id": "task-1", "capabilities": [COLIBRI_CAPABILITY], "allowed_effects": ["external_effect"]}
    value.update(overrides)
    return value


def effect(**overrides):
    value = {
        "effect_id": "effect-1",
        "attempt_id": "attempt-1",
        "state": "DISPATCHED",
        "payload": {"messages": [{"role": "user", "content": "hello"}], "max_tokens": 32},
    }
    value.update(overrides)
    return value


def adapter(body=None, **kwargs):
    return ColibriAdapter(
        model="test-model",
        opener=lambda request, timeout: response(body),
        **kwargs,
    )


def test_valid_response_is_bound_to_effect_and_attempt():
    receipt = adapter().execute(contract=authorized_contract(), effect=effect(), attempt_id="attempt-1")
    assert receipt.provider == "colibri.inference"
    assert receipt.effect_id == "effect-1"
    assert receipt.attempt_id == "attempt-1"
    assert receipt.outcome == "OBSERVED_SUCCESS"
    observed = receipt.observation["colibri_response"]
    assert observed["message"]["content"] == "hello"
    assert len(observed["request_sha256"]) == 64
    assert observed["endpoint"] == "http://127.0.0.1:8000/v1/chat/completions"


def test_missing_capability_fails_closed():
    with pytest.raises(PermissionError, match="capability"):
        adapter().execute(contract=authorized_contract(capabilities=[]), effect=effect(), attempt_id="attempt-1")


def test_missing_external_effect_permission_fails_closed():
    with pytest.raises(PermissionError, match="external effect"):
        adapter().execute(contract=authorized_contract(allowed_effects=[]), effect=effect(), attempt_id="attempt-1")


def test_wrong_attempt_binding_rejected_before_request():
    with pytest.raises(ValueError, match="attempt binding"):
        adapter().execute(contract=authorized_contract(), effect=effect(attempt_id="other"), attempt_id="attempt-1")


def test_undispatched_effect_rejected():
    with pytest.raises(RuntimeError, match="dispatched"):
        adapter().execute(contract=authorized_contract(), effect=effect(state="PLANNED"), attempt_id="attempt-1")


def test_non_loopback_endpoint_rejected():
    with pytest.raises(PermissionError, match="loopback"):
        ColibriAdapter(model="test-model", base_url="https://example.com/v1").execute(
            contract=authorized_contract(), effect=effect(), attempt_id="attempt-1"
        )


def test_invalid_max_tokens_rejected():
    with pytest.raises(ValueError, match="max_tokens"):
        adapter().execute(contract=authorized_contract(), effect=effect(payload={
            "messages": [{"role": "user", "content": "hello"}], "max_tokens": True,
        }), attempt_id="attempt-1")


def test_oversized_response_rejected():
    body = {"id": "x" * 80, "choices": [{"message": {"content": "hello"}}]}
    with pytest.raises(ValueError, match="exceeds output limit"):
        adapter(body, max_response_bytes=32).execute(
            contract=authorized_contract(), effect=effect(), attempt_id="attempt-1"
        )


def test_malformed_response_rejected():
    with pytest.raises(ValueError, match="no choices"):
        adapter({"id": "chatcmpl-test-1", "choices": []}).execute(
            contract=authorized_contract(), effect=effect(), attempt_id="attempt-1"
        )


def test_missing_response_id_rejected():
    with pytest.raises(ValueError, match="response.id"):
        adapter({"choices": [{"message": {"content": "hello"}}]}).execute(
            contract=authorized_contract(), effect=effect(), attempt_id="attempt-1"
        )


def test_request_size_is_bounded():
    with pytest.raises(ValueError, match="input limit"):
        adapter(max_request_bytes=20).execute(
            contract=authorized_contract(), effect=effect(), attempt_id="attempt-1"
        )


def test_provider_name_matches_aios_capability_resolution():
    from core.runtime import _provider_authorized
    assert _provider_authorized(authorized_contract(), "colibri.inference") is True
    assert _provider_authorized(authorized_contract(), "colibri") is False
