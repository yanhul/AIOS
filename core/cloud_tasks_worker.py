"""Fail-closed Cloud Tasks and Scheduler HTTP endpoints.

Cloud Run IAM is the outer authentication boundary. Production wiring also
verifies the caller's Google-signed ID token and expected service-account email
so the Scheduler identity cannot forge a Cloud Tasks delivery header.
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Mapping
from wsgiref.util import setup_testing_defaults

from .cloud_tasks_contract import (
    DispatchTaskRejected, deterministic_task_name, validate_dispatch_task,
)


def handle_dispatch_delivery(
    payload: Mapping[str, Any], *, store: Any, now: float,
    reconcile_same_attempt: Callable[..., Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Handle one Cloud Tasks delivery; never authorize fresh execution."""
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
        same_attempt = store.resume_same_attempt(effect_id=effect_id, attempt_id=attempt_id)
        if reconcile_same_attempt is None:
            return 503, {"status": "RECONCILIATION_ADAPTER_UNAVAILABLE",
                         "effect_id": effect_id, "attempt_id": attempt_id}
        reconcile_same_attempt(effect=same_attempt["effect"], attempt=same_attempt["attempt"])
        latest = store.get_effect(effect_id)
        latest_attempt = store.get_attempt(effect_id, attempt_id)
        if latest is None or latest_attempt is None:
            return 503, {"status": "AUTHORITATIVE_READBACK_UNAVAILABLE"}
        if (latest.get("state") in {"OBSERVED_SUCCESS", "OBSERVED_FAILURE"}
                and latest_attempt.get("state") == latest.get("state")):
            return 204, {"status": "ACK_TERMINAL"}
        return 503, {"status": "SAME_ATTEMPT_STILL_UNRESOLVED"}
    except DispatchTaskRejected as exc:
        return 400, {"status": "REJECTED", "reason": str(exc)}
    except Exception:
        return 503, {"status": "RECONCILIATION_UNCONFIRMED"}


def create_app(
    *,
    store_factory: Callable[[], Any] | None = None,
    reconcile_same_attempt: Callable[..., Any] | None = None,
    outbox_reconciler: Callable[[], Mapping[str, Any]] | None = None,
    authorize_request: Callable[[Mapping[str, Any], str], bool] | None = None,
) -> Callable[..., Any]:
    """Build a WSGI app; production must inject identity and reconciliation hooks."""
    if store_factory is None:
        from .firestore_worker import create_firestore_effect_store
        store_factory = create_firestore_effect_store

    def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
        setup_testing_defaults(environ)
        path = environ.get("PATH_INFO", "")
        if path not in {"/dispatch", "/outbox/reconcile"}:
            result, response = 404, {"status": "NOT_FOUND"}
        elif environ.get("REQUEST_METHOD") != "POST":
            result, response = 405, {"status": "METHOD_NOT_ALLOWED"}
        elif authorize_request is not None and not authorize_request(environ, path):
            result, response = 403, {"status": "CALLER_NOT_AUTHORIZED"}
        elif path == "/outbox/reconcile":
            if outbox_reconciler is None:
                result, response = 503, {"status": "OUTBOX_RECONCILER_UNAVAILABLE"}
            else:
                try:
                    summary = dict(outbox_reconciler())
                    failed = summary.get("failed", [])
                    result = 503 if failed else 200
                    response = {
                        "status": "OUTBOX_RECONCILIATION_PARTIAL" if failed else "OUTBOX_RECONCILIATION_OK",
                        "scanned": summary.get("scanned", 0),
                        "published_count": len(summary.get("published", [])),
                        "failed_count": len(failed),
                    }
                except Exception:
                    result, response = 503, {"status": "OUTBOX_RECONCILIATION_UNCONFIRMED"}
        else:
            task_name = environ.get("HTTP_X_CLOUDTASKS_TASKNAME", "")
            if not task_name:
                result, response = 400, {"status": "TASK_IDENTITY_REQUIRED"}
            else:
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
                        payload, store=store_factory(), now=time.time(),
                        reconcile_same_attempt=reconcile_same_attempt,
                    )
                except (ValueError, TypeError, json.JSONDecodeError):
                    result, response = 400, {"status": "BAD_REQUEST"}
                except Exception:
                    result, response = 503, {"status": "WORKER_UNAVAILABLE"}

        phrase = {
            200: "OK", 204: "No Content", 400: "Bad Request",
            403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
            503: "Service Unavailable",
        }.get(result, "Internal Server Error")
        body = b"" if result == 204 else json.dumps(response, sort_keys=True).encode("utf-8")
        start_response(f"{result} {phrase}", [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
        ])
        return [body]

    return application


__all__ = ["handle_dispatch_delivery", "create_app"]
