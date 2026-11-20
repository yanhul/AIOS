import pytest

from core.cloud_tasks_outbox import (
    publish_dispatch_outbox_item, reconcile_dispatch_outbox_batch,
)
from core.cloud_tasks_publisher import CloudTasksPublishError


class Store:
    def __init__(self):
        self.record = {
            "state": "PENDING", "expected_revision": 1,
            "effect_id": "EF-outbox-1", "attempt_id": "EF-outbox-1:attempt:1",
        }
        self.released = False
        self.published = False

    def claim_dispatch_outbox(self, **kwargs):
        if self.record["state"] == "PUBLISHED":
            return dict(self.record)
        self.record["state"] = "LEASED"
        self.record["lease_owner"] = kwargs["lease_owner"]
        return dict(self.record)

    def release_dispatch_outbox(self, **kwargs):
        self.released = True
        self.record["state"] = "PENDING"
        self.record.pop("lease_owner", None)
        return dict(self.record)

    def mark_dispatch_outbox_published(self, **kwargs):
        assert self.record["lease_owner"] == kwargs["lease_owner"]
        self.published = True
        self.record["state"] = "PUBLISHED"
        return dict(self.record)


class Tasks:
    def __init__(self, fail=False):
        self.fail = fail
        self.requests = []

    def queue_path(self, project, location, queue):
        return f"projects/{project}/locations/{location}/queues/{queue}"

    def task_path(self, project, location, queue, task):
        return self.queue_path(project, location, queue) + "/tasks/" + task

    def create_task(self, request):
        if self.fail:
            raise TimeoutError("ambiguous enqueue")
        self.requests.append(request)


def args(store, client):
    return dict(
        store=store, client=client, project="emulator", location="asia-southeast1",
        queue="aios", target_url="https://worker.example/dispatch",
        oidc_service_account="worker@emulator.iam.gserviceaccount.com",
        oidc_audience="https://worker.example",
        effect_id="EF-outbox-1", attempt_id="EF-outbox-1:attempt:1",
        lease_owner="publisher-1", now=1000, lease_seconds=30,
        task_ttl_seconds=300,
    )


def test_outbox_publisher_enqueues_then_persists_ack():
    store, client = Store(), Tasks()
    result = publish_dispatch_outbox_item(**args(store, client))
    assert result["state"] == "PUBLISHED"
    assert result["task_id"].startswith("aios-")
    assert store.published is True
    assert len(client.requests) == 1


def test_ambiguous_enqueue_releases_same_outbox_for_reconciliation():
    store, client = Store(), Tasks(fail=True)
    with pytest.raises(CloudTasksPublishError, match="reconcile"):
        publish_dispatch_outbox_item(**args(store, client))
    assert store.released is True
    assert store.record["state"] == "PENDING"
    assert store.published is False


def test_batch_reconciler_scans_and_publishes_bounded_outbox_items():
    store, client = Store(), Tasks()
    store.list_dispatch_outbox_candidates = lambda **kwargs: [dict(store.record)]
    result = reconcile_dispatch_outbox_batch(
        store=store, client=client, project="emulator", location="asia-southeast1",
        queue="aios", target_url="https://worker.example/dispatch",
        oidc_service_account="worker@emulator.iam.gserviceaccount.com",
        lease_owner="publisher-batch", now=1000, lease_seconds=30,
        limit=10, task_ttl_seconds=300,
    )
    assert result["scanned"] == 1
    assert len(result["published"]) == 1
    assert result["failed"] == []
