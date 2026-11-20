"""Cloud Tasks publisher for an already committed Firestore dispatch intent.

This adapter only transports an immutable reference. It never authorizes an
effect, creates an attempt, or invokes a provider. Callers must persist the
dispatch intent/outbox record before calling publish_dispatch_task().
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .cloud_tasks_contract import (
    SCHEMA, deterministic_task_name, dispatch_event_digest,
)


class CloudTasksPublishError(RuntimeError):
    """Task enqueue was not confirmed; reconcile deterministic task identity."""


def build_dispatch_envelope(*, effect_id: str, attempt_id: str,
                            expected_revision: int, issued_at: float,
                            expires_at: float) -> dict[str, Any]:
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 1:
        raise ValueError("expected_revision must be a positive integer")
    if not isinstance(issued_at, (int, float)) or not isinstance(expires_at, (int, float)):
        raise ValueError("issued_at and expires_at must be numeric")
    if expires_at <= issued_at:
        raise ValueError("expires_at must be after issued_at")
    return {
        "schema": SCHEMA,
        "effect_id": effect_id,
        "attempt_id": attempt_id,
        "expected_revision": expected_revision,
        "dispatch_event_digest": dispatch_event_digest(effect_id, attempt_id),
        "issued_at": float(issued_at),
        "expires_at": float(expires_at),
    }


def publish_dispatch_task(*, client: Any, project: str, location: str, queue: str,
                          target_url: str, oidc_service_account: str,
                          payload: Mapping[str, Any]) -> str:
    """Enqueue a committed dispatch reference using deterministic task naming.

    The injected client is the official Cloud Tasks client in production. Tests
    use a fake. An ambiguous API error is surfaced; callers reconcile by the
    deterministic task name and must not allocate another effect attempt.
    """
    for value, label in ((project, "project"), (location, "location"),
                         (queue, "queue"), (oidc_service_account, "oidc_service_account")):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} is required")
    if not isinstance(target_url, str) or not target_url.startswith("https://"):
        raise ValueError("target_url must use HTTPS")
    if not isinstance(payload, Mapping) or payload.get("schema") != SCHEMA:
        raise ValueError("valid dispatch envelope required")
    task_id = deterministic_task_name(payload.get("effect_id"), payload.get("attempt_id"))
    parent = client.queue_path(project, location, queue)
    name = client.task_path(project, location, queue, task_id)
    body = json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")
    task = {
        "name": name,
        "http_request": {
            "http_method": "POST",
            "url": target_url,
            "headers": {"Content-Type": "application/json"},
            "body": body,
            "oidc_token": {"service_account_email": oidc_service_account},
        },
    }
    try:
        client.create_task(request={"parent": parent, "task": task})
    except Exception as exc:
        # Cloud Tasks ALREADY_EXISTS is positive evidence that this exact
        # deterministic task resource already exists. Its name binds the same
        # effect/attempt; do not create another task identity.
        code = getattr(exc, "code", None)
        code = code() if callable(code) else code
        if code == 409 or getattr(code, "value", None) == 6 or type(exc).__name__ == "AlreadyExists":
            return task_id
        raise CloudTasksPublishError(
            f"Cloud Tasks enqueue unconfirmed for deterministic task {task_id}; reconcile before retry"
        ) from exc
    return task_id


__all__ = ["CloudTasksPublishError", "build_dispatch_envelope", "publish_dispatch_task"]
