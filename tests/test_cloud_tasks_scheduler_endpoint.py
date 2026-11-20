import io
import json

from core.cloud_tasks_worker import create_app


def _request(app, path, *, method="POST", auth="trusted", body=b"{}"):
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "HTTP_AUTHORIZATION": auth,
    }
    response = b"".join(app(environ, start_response))
    return captured["status"], json.loads(response) if response else None


def test_scheduler_endpoint_requires_scheduler_identity_and_reports_batch_result():
    seen = []
    app = create_app(
        outbox_reconciler=lambda: {"scanned": 2, "published": ["a"], "failed": []},
        authorize_request=lambda env, path: env["HTTP_AUTHORIZATION"] == "scheduler" and path == "/outbox/reconcile",
    )
    denied, _ = _request(app, "/outbox/reconcile", auth="cloud-tasks")
    ok, body = _request(app, "/outbox/reconcile", auth="scheduler")
    assert denied.startswith("403")
    assert ok.startswith("200")
    assert body == {
        "status": "OUTBOX_RECONCILIATION_OK",
        "scanned": 2,
        "published_count": 1,
        "failed_count": 0,
    }


def test_scheduler_endpoint_returns_retryable_failure_for_partial_batch():
    app = create_app(
        outbox_reconciler=lambda: {"scanned": 2, "published": ["a"], "failed": [{"task_id": "b"}]},
        authorize_request=lambda env, path: True,
    )
    status, body = _request(app, "/outbox/reconcile")
    assert status.startswith("503")
    assert body["status"] == "OUTBOX_RECONCILIATION_PARTIAL"
    assert body["failed_count"] == 1


def test_scheduler_endpoint_fails_closed_without_reconciler():
    app = create_app(authorize_request=lambda env, path: True)
    status, body = _request(app, "/outbox/reconcile")
    assert status.startswith("503")
    assert body["status"] == "OUTBOX_RECONCILER_UNAVAILABLE"


def test_production_route_authorizer_is_called_before_dispatch_body_processing():
    seen = []
    app = create_app(
        authorize_request=lambda env, path: seen.append(path) or False,
        store_factory=lambda: object(),
    )
    status, body = _request(app, "/dispatch", body=b"not-json")
    assert status.startswith("403")
    assert body["status"] == "CALLER_NOT_AUTHORIZED"
    assert seen == ["/dispatch"]
