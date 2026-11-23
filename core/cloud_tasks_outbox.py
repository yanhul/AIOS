"""Durable Firestore dispatch-outbox publisher.

A batch runner can scan Firestore outbox candidates and call
publish_dispatch_outbox_item. The deterministic task identity makes a retry
safe after a crash between Cloud Tasks acceptance and Firestore acknowledgement.
"""
from __future__ import annotations

from typing import Any

from .cloud_tasks_publisher import (
    CloudTasksPublishError, build_dispatch_envelope, publish_dispatch_task,
)


def publish_dispatch_outbox_item(
    *, store: Any, client: Any, project: str, location: str, queue: str,
    target_url: str, oidc_service_account: str, oidc_audience: str, effect_id: str, attempt_id: str,
    lease_owner: str, now: float, lease_seconds: int, task_ttl_seconds: int,
) -> dict[str, Any]:
    """Publish one committed outbox item and persist acknowledgement.

    If enqueue is ambiguous, the lease is released and the same deterministic
    task identity remains pending. No new effect attempt is allocated.
    """
    if isinstance(task_ttl_seconds, bool) or not isinstance(task_ttl_seconds, int) or task_ttl_seconds < 1:
        raise ValueError("task_ttl_seconds must be a positive integer")
    claimed = store.claim_dispatch_outbox(
        effect_id=effect_id, attempt_id=attempt_id, lease_owner=lease_owner,
        now=now, lease_seconds=lease_seconds,
    )
    if claimed.get("state") == "PUBLISHED":
        return claimed
    payload = build_dispatch_envelope(
        effect_id=effect_id, attempt_id=attempt_id,
        expected_revision=claimed["expected_revision"],
        issued_at=now, expires_at=now + task_ttl_seconds,
    )
    try:
        task_id = publish_dispatch_task(
            client=client, project=project, location=location, queue=queue,
            target_url=target_url, oidc_service_account=oidc_service_account,
            oidc_audience=oidc_audience, payload=payload,
        )
    except Exception as exc:
        try:
            store.release_dispatch_outbox(
                effect_id=effect_id, attempt_id=attempt_id,
                lease_owner=lease_owner, error=type(exc).__name__,
            )
        except Exception as release_exc:
            raise CloudTasksPublishError(
                "enqueue outcome and outbox lease release are both unconfirmed; reconcile same task identity"
            ) from release_exc
        if isinstance(exc, CloudTasksPublishError):
            raise
        raise CloudTasksPublishError("outbox enqueue failed; reconcile same task identity") from exc
    published = store.mark_dispatch_outbox_published(
        effect_id=effect_id, attempt_id=attempt_id,
        lease_owner=lease_owner, published_at=now,
    )
    return dict(published, task_id=task_id)



def reconcile_dispatch_outbox_batch(
    *, store: Any, client: Any, project: str, location: str, queue: str,
    target_url: str, oidc_service_account: str, oidc_audience: str, lease_owner: str, now: float, lease_seconds: int,
    limit: int, task_ttl_seconds: int,
) -> dict[str, Any]:
    """Publish a bounded batch of pending/expired outbox obligations."""
    candidates = store.list_dispatch_outbox_candidates(now=now, limit=limit)
    published: list[str] = []
    failed: list[dict[str, str]] = []
    for item in candidates:
        effect_id, attempt_id = item.get("effect_id"), item.get("attempt_id")
        if not isinstance(effect_id, str) or not isinstance(attempt_id, str):
            failed.append({"task_id": str(item.get("task_id", "")), "error": "invalid_outbox_identity"})
            continue
        try:
            result = publish_dispatch_outbox_item(
                store=store, client=client, project=project, location=location,
                queue=queue, target_url=target_url,
                oidc_service_account=oidc_service_account, oidc_audience=oidc_audience,
                effect_id=effect_id, attempt_id=attempt_id,
                lease_owner=lease_owner, now=now, lease_seconds=lease_seconds,
                task_ttl_seconds=task_ttl_seconds,
            )
            published.append(str(result.get("task_id", item.get("task_id", ""))))
        except Exception as exc:
            failed.append({
                "task_id": str(item.get("task_id", "")),
                "error": type(exc).__name__,
            })
    return {"scanned": len(candidates), "published": published, "failed": failed}


__all__ = ["publish_dispatch_outbox_item", "reconcile_dispatch_outbox_batch"]

