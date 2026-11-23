import pytest

from core.cloud_run_worker import (
    CloudRunWorkerConfigurationError,
    _load_adapter_factory,
    _positive_int,
    _verify_caller,
    load_attestation_secret,
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


class _SecretPayload:
    data = b"attestation-secret-material"


class _SecretResponse:
    payload = _SecretPayload()


class _FakeSecretManager:
    def __init__(self, fail=False):
        self.fail = fail
        self.names = []

    def access_secret_version(self, request):
        self.names.append(request["name"])
        if self.fail:
            raise RuntimeError("permission denied")
        return _SecretResponse()


def test_worker_loads_only_pinned_secret_manager_version():
    client = _FakeSecretManager()
    secret = load_attestation_secret(
        {"AIOS_AUTHORITY_ATTESTATION_SECRET_VERSION":
         "projects/aios-test/secrets/attestation/versions/7"},
        client=client,
    )
    assert secret == "attestation-secret-material"
    assert client.names == [
        "projects/aios-test/secrets/attestation/versions/7"
    ]


def test_worker_secret_manager_failure_fails_closed():
    with pytest.raises(CloudRunWorkerConfigurationError, match="DENY"):
        load_attestation_secret(
            {"AIOS_AUTHORITY_ATTESTATION_SECRET_VERSION":
             "projects/aios-test/secrets/attestation/versions/7"},
            client=_FakeSecretManager(fail=True),
        )


def test_worker_rejects_unpinned_or_latest_secret_version():
    for version in ("", "projects/test/secrets/attestation/versions/latest"):
        with pytest.raises(CloudRunWorkerConfigurationError):
            load_attestation_secret(
                {"AIOS_AUTHORITY_ATTESTATION_SECRET_VERSION": version},
                client=_FakeSecretManager(),
            )
