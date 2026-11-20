import pytest

from core.secret_manager import SecretMaterialUnavailable, read_hmac_attestation_secret


class Payload:
    data = b"0123456789abcdef-secret"


class Response:
    payload = Payload()


class FakeSecretManager:
    def __init__(self, fail=False):
        self.fail = fail
        self.names = []

    def access_secret_version(self, request):
        self.names.append(request["name"])
        if self.fail:
            raise RuntimeError("permission denied")
        return Response()


def test_reads_only_explicit_numeric_secret_version():
    client = FakeSecretManager()
    secret = read_hmac_attestation_secret(
        client=client,
        version_resource="projects/aios-test/secrets/attestation/versions/3",
    )
    assert secret == "0123456789abcdef-secret"
    assert client.names == ["projects/aios-test/secrets/attestation/versions/3"]


@pytest.mark.parametrize("name", [
    "projects/test/secrets/attestation/versions/latest",
    "projects/test/secrets/attestation",
    "",
])
def test_rejects_alias_or_unversioned_secret_reference(name):
    with pytest.raises(SecretMaterialUnavailable):
        read_hmac_attestation_secret(client=FakeSecretManager(), version_resource=name)


def test_secret_manager_permission_failure_fails_closed():
    with pytest.raises(SecretMaterialUnavailable, match="DENY"):
        read_hmac_attestation_secret(
            client=FakeSecretManager(fail=True),
            version_resource="projects/test/secrets/attestation/versions/4",
        )
