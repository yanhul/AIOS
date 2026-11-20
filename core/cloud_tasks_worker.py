"""Fail-closed Cloud Tasks HTTP endpoint for same-attempt reconciliation.

Cloud Run IAM must require the configured Cloud Tasks OIDC service identity.
This handler never calls a provider and never allocates a new attempt. A real
reconciliation adapter must be injected only after durable authority checks
are implemented and independently verified.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Mapping
from wsgiref.util import setup_testing_defaults

from .cloud_tasks_contract import (
    DispatchTaskRejected, deterministic_task_name, validate_dispatch_task,
)


def handle_dispatch_delivery(
    payload: Mapping[str, Any], *, store: Any, now: float,
    reconcile_same_attempt: Callable[..., Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Handle one Cloud Tasks delivery; no path here authorizes fresh execution."""
    effect_id = payload.get("effect_id") if isinstance(payload, Mapping) else None
    attempt_id = payload.get("attempt_id") if isinstance(payload, Mapping) else None
    if not isinstance(effect_id, str) or not isinstance(attempt_id, str):
        return 400, {"status": "REJECTED", "reason": "effect/attempt identity missing"}
    try:
        effect = store.get_effect(effect_id)
        attempt = store.get_attempt(effect_id, attempt_id)
        if effect is None or attempt is None:
            raise DispatchTaskRejected("authoritative effect or attempt is missing")
        decision = validate_dispatch_task(payload, effect=effect, attempt=attempt, now=now)
        if decision == "ACK_TERMINAL":
            return 204, {"status": "ACK_TERMINAL"}
        # A fresh process resumes the exact persisted attempt. This is a read,
        # not a dispatch and not permission to invoke a provider.
        same_attempt = store.resume_same_attempt(effect_id=effect_id, attempt_id=attempt_id)
        if reconcile_same_attempt is None:
            return 503, {
                "status": "RECONCILIATION_ADAPTER_UNAVAILABLE",
                "effect_id": effect_id,
                "attempt_id": attempt_id,
            }
        reconcile_same_attempt(effect=same_attempt["effect"], attempt=same_attempt["attempt"])
        latest = store.get_effect(effect_id)
        latest_attempt = store.get_attempt(effect_id, attempt_id)
        if latest is None or latest_attempt is None:
            return 503, {"status": "AUTHORITATIVE_READBACK_UNAVAILABLE"}
        if latest.get("state") in {"OBSERVED_SUCCESS", "OBSERVED_FAILURE"} and latest_attempt.get("state") == latest.get("state"):
            return 204, {"status": "ACK_TERMINAL"}
        # Cloud Tasks retries the same task. It does not create a new attempt.
        return 503, {"status": "SAME_ATTEMPT_STILL_UNRESOLVED"}
    except DispatchTaskRejected as exc:
        return 400, {"status": "REJECTED", "reason": str(exc)}
    except Exception:
        # Avoid leaking provider or authority details to the transport caller.
        return 503, {"status": "RECONCILIATION_UNCONFIRMED"}


def create_app(
    *, store_factory: Callable[[], Any] | None = None,
    reconcile_same_attempt: Callable[..., Any] | None = None,
) -> Callable[..., Any]:
    """Return a dependency-free WSGI app suitable for a private Cloud Run service."""
    if store_factory is None:
        from .firestore_worker import create_firestore_effect_store
        store_factory = create_firestore_effect_store

    def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
        setup_testing_defaults(environ)
        if environ.get("PATH_INFO") != "/dispatch" or environ.get("REQUEST_METHOD") != "POST":
            body = b'{"status":"NOT_FOUND"}'
            start_response("404 Not Found", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]
        task_name = environ.get("HTTP_X_CLOUDTASKS_TASKNAME", "")
        if not task_name:
            body = b'{"status":"TASK_IDENTITY_REQUIRED"}'
            start_response("400 Bad Request", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
            if length < 1 or length > 65536:
                raise ValueError("invalid request size")
            payload = json.loads(environ["wsgi.input"].read(length))
            if not isinstance(payload, dict):
                raise ValueError("JSON object required")
            expected = deterministic_task_name(payload.get("effect_id"), payload.get("attempt_id"))
            if not task_name.endswith("/tasks/" + expected):
                raise ValueError("Cloud Tasks name does not match payload identity")
            result, response = handle_dispatch_delivery(
                payload, store=store_factory(), now=__import__("time").time(),
                reconcile_same_attempt=reconcile_same_attempt,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            result, response = 400, {"status": "BAD_REQUEST"}
        except Exception:
            result, response = 503, {"status": "WORKER_UNAVAILABLE"}
        phrase = {204: "No Content", 400: "Bad Request", 503: "Service Unavailable"}.get(result, "OK")
        body = b"" if result == 204 else json.dumps(response, sort_keys=True).encode("utf-8")
        start_response(f"{result} {phrase}", [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ])
        return [body]

    return application


__all__ = ["handle_dispatch_delivery", "create_app"]
