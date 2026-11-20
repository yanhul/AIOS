import pytest

from core.cloud_run_worker import (
    CloudRunWorkerConfigurationError,
    _load_adapter_factory,
    _positive_int,
    _verify_caller,
)


def test_adapter_factory_path_is_confined_to_trusted_extension_package():
    with pytest.raises(CloudRunWorkerConfigurationError, match="package"):
        _load_adapter_factory("core.runtime:execute_attempt")
    with pytest.raises(CloudRunWorkerConfigurationError, match="module:callable"):
        _load_adapter_factory("aios_worker_adapters.factory")


def test_batch_and_lease_values_must_be_explicit_positive_integers():
    assert _positive_int({"LIMIT": "8"}, "LIMIT") == 8
    for raw in ("", "0", "-1", "1.5", "NaN"):
        with pytest.raises(CloudRunWorkerConfigurationError):
            _positive_int({"LIMIT": raw}, "LIMIT")


def test_identity_verification_rejects_missing_bearer_token():
    assert _verify_caller({}, audience="https://worker.example", expected_email="tasks@example.iam.gserviceaccount.com") is False
    assert _verify_caller(
        {"HTTP_AUTHORIZATION": "Basic abc"},
        audience="https://worker.example",
        expected_email="tasks@example.iam.gserviceaccount.com",
    ) is False
