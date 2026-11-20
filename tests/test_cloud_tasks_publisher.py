import pytest

from core.cloud_tasks_contract import SCHEMA
from core.cloud_tasks_publisher import (
    CloudTasksPublishError, build_dispatch_envelope, publish_dispatch_task,
)


class FakeCloudTasks:
    def __init__(self, fail=False):
        self.fail = fail
        self.requests = []

    def queue_path(self, project, location, queue):
        return f"projects/{project}/locations/{location}/queues/{queue}"

    def task_path(self, project, location, queue, task):
        return self.queue_path(project, location, queue) + "/tasks/" + task

    def create_task(self, request):
        if self.fail:
            raise TimeoutError("simulated ambiguous enqueue")
        self.requests.append(request)


def test_dispatch_envelope_has_stable_task_identity():
    payload = build_dispatch_envelope(
        effect_id="EF-1", attempt_id="EF-1:attempt:1",
        expected_revision=1, issued_at=100, expires_at=200,
    )
    assert payload["schema"] == SCHEMA
    client = FakeCloudTasks()
    first = publish_dispatch_task(
        client=client, project="test", location="asia-southeast1", queue="aios",
        target_url="https://worker.example/dispatch",
        oidc_service_account="worker@test.iam.gserviceaccount.com", payload=payload,
    )
    second = publish_dispatch_task(
        client=client, project="test", location="asia-southeast1", queue="aios",
        target_url="https://worker.example/dispatch",
        oidc_service_account="worker@test.iam.gserviceaccount.com", payload=payload,
    )
    assert first == second
    assert len(client.requests) == 2
    assert client.requests[0]["task"]["http_request"]["oidc_token"]["service_account_email"].startswith("worker@")


def test_ambiguous_enqueue_is_not_silently_retried_with_new_identity():
    payload = build_dispatch_envelope(
        effect_id="EF-1", attempt_id="EF-1:attempt:1",
        expected_revision=1, issued_at=100, expires_at=200,
    )
    with pytest.raises(CloudTasksPublishError, match="reconcile"):
        publish_dispatch_task(
            client=FakeCloudTasks(fail=True), project="test", location="us-central1",
            queue="aios", target_url="https://worker.example/dispatch",
            oidc_service_account="worker@test.iam.gserviceaccount.com", payload=payload,
        )


def test_rejects_non_https_or_untrusted_task_shape():
    client = FakeCloudTasks()
    payload = build_dispatch_envelope(
        effect_id="EF-1", attempt_id="EF-1:attempt:1",
        expected_revision=1, issued_at=100, expires_at=200,
    )
    with pytest.raises(ValueError, match="HTTPS"):
        publish_dispatch_task(
            client=client, project="test", location="us-central1", queue="aios",
            target_url="http://worker.example/dispatch",
            oidc_service_account="worker@test.iam.gserviceaccount.com", payload=payload,
        )


def test_cloud_tasks_already_exists_confirms_same_deterministic_task():
    class AlreadyExists(Exception):
        code = 409

    class ExistingTaskClient(FakeCloudTasks):
        def create_task(self, request):
            raise AlreadyExists("task already exists")

    payload = build_dispatch_envelope(
        effect_id="EF-1", attempt_id="EF-1:attempt:1",
        expected_revision=1, issued_at=100, expires_at=200,
    )
    task_id = publish_dispatch_task(
        client=ExistingTaskClient(), project="test", location="asia-southeast1",
        queue="aios", target_url="https://worker.example/dispatch",
        oidc_service_account="worker@test.iam.gserviceaccount.com", payload=payload,
    )
    assert task_id.startswith("aios-")
