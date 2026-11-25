import base64
import hashlib
import time
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.mutation import canonical_json
from core.algorithm_worker_receipt import (
    AlgorithmWorkerKeyring, RECEIPT_ISSUER, RECEIPT_SCOPE, SIGNED_FIELDS,
)
from core.algorithm_worker_artifact import (
    AlgorithmWorkerArtifactError, verify_algorithm_worker_artifact,
)


def fixture(path=None, grid=None):
    grid = grid or ["S..", ".#.", "..G"]
    spec = {"operation": "maze.shortest_path", "version": 1, "max_expansions": 100}
    artifact = {
        "schema": "try.algorithm-artifact.v1", "operation": "maze.shortest_path",
        "version": 1, "path": path if path is not None else [[0, 0], [0, 1], [0, 2], [1, 2], [2, 2]],
        "expansions": 8,
    }
    artifact_bytes = canonical_json(artifact).encode("utf-8")
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keyring = AlgorithmWorkerKeyring({RECEIPT_ISSUER: {
        "public_key": base64.b64encode(public).decode("ascii"),
        "key_id": "algorithm-worker-artifact-test-v1",
        "scopes": [RECEIPT_SCOPE], "revoked": False,
    }})
    expected = {
        "contract_id": "CT-1", "permit_id": "PM-1", "execution_id": "EX-1",
        "effect_id": "EF-1", "dispatch_id": "DP-1", "dispatch_digest": "8" * 64,
        "attempt_id": "EX-1:attempt:1", "attempt_number": 1,
        "worker_id": "try-worker-prod-a", "worker_build_sha256": "a" * 64,
        "executor_revision": "b" * 40, "executor_sha256": "c" * 64,
        "spec_sha256": hashlib.sha256(canonical_json(spec).encode()).hexdigest(),
        "input_sha256": hashlib.sha256(canonical_json({"grid": grid}).encode()).hexdigest(),
    }
    now = time.time()
    artifact_digest = hashlib.sha256(artifact_bytes).hexdigest()
    receipt = {
        "type": "TRY_ALGORITHM_EXECUTION_RECEIPT_V1", "issuer": RECEIPT_ISSUER,
        "key_id": "algorithm-worker-artifact-test-v1", "receipt_id": "TA-" + "1" * 32,
        **expected, "artifact_sha256": artifact_digest, "output_sha256": artifact_digest,
        "status": "COMPLETED", "execution_state": "COMPLETED",
        "issued_at": now, "expires_at": now + 300, "algorithm": "Ed25519",
    }
    signed = {field: receipt[field] for field in SIGNED_FIELDS}
    receipt["signature"] = base64.b64encode(
        private.sign(canonical_json(signed).encode("utf-8"))
    ).decode("ascii")
    result = verify_algorithm_worker_artifact(
        receipt, artifact_bytes, expected=expected, grid=grid, spec=spec,
        expected_executor_revision="b" * 40, expected_executor_sha256="c" * 64,
        keyring=keyring,
    )
    return result, receipt, artifact_bytes, expected, spec, grid, keyring, private


def test_signed_artifact_is_hashed_and_independently_verified():
    result, *_ = fixture()
    assert result["status"] == "INDEPENDENTLY_VERIFIED"
    assert result["oracle_distance"] == 4
    assert result["candidate_distance"] == 4
    assert result["retry_authorized"] is False
    assert result["promotion"] == "NOT_AUTHORIZED"


def test_artifact_bytes_must_match_signed_digest():
    _, receipt, artifact_bytes, expected, spec, grid, keyring, _private = fixture()
    tampered = artifact_bytes + b" "
    with pytest.raises(AlgorithmWorkerArtifactError, match="artifact bytes do not match"):
        verify_algorithm_worker_artifact(
            receipt, tampered, expected=expected, grid=grid, spec=spec,
            expected_executor_revision="b" * 40, expected_executor_sha256="c" * 64,
            keyring=keyring,
        )


def test_signed_but_nonoptimal_path_is_rejected():
    _, receipt, _, expected, spec, grid, keyring, private = fixture(
        path=[[0, 0], [0, 1], [0, 2]], grid=["S.G", "..."]
    )
    bad_artifact = {
        "schema": "try.algorithm-artifact.v1", "operation": "maze.shortest_path",
        "version": 1,
        "path": [[0, 0], [1, 0], [1, 1], [0, 1], [0, 2]],
        "expansions": 8,
    }
    raw = canonical_json(bad_artifact).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    bad_receipt = dict(receipt, artifact_sha256=digest, output_sha256=digest)
    signed = {field: bad_receipt[field] for field in SIGNED_FIELDS}
    bad_receipt["signature"] = base64.b64encode(
        private.sign(canonical_json(signed).encode("utf-8"))
    ).decode("ascii")
    with pytest.raises(AlgorithmWorkerArtifactError, match="not shortest"):
        verify_algorithm_worker_artifact(
            bad_receipt, raw, expected=expected, grid=["S.G", "..."],
            spec=spec, expected_executor_revision="b" * 40,
            expected_executor_sha256="c" * 64, keyring=keyring,
        )


def test_unknown_receipt_cannot_be_used_as_completed_artifact():
    _, receipt, artifact_bytes, expected, spec, grid, keyring, private = fixture()
    unknown = dict(
        receipt, status="UNKNOWN", execution_state="IN_PROGRESS_OR_AMBIGUOUS",
        artifact_sha256=None, output_sha256=None,
    )
    signed = {field: unknown[field] for field in SIGNED_FIELDS}
    unknown["signature"] = base64.b64encode(
        private.sign(canonical_json(signed).encode("utf-8"))
    ).decode("ascii")
    with pytest.raises(AlgorithmWorkerArtifactError, match="receipt is UNKNOWN"):
        verify_algorithm_worker_artifact(
            unknown, artifact_bytes, expected=expected, grid=grid, spec=spec,
            expected_executor_revision="b" * 40, expected_executor_sha256="c" * 64,
            keyring=keyring,
        )


def test_duplicate_json_keys_are_rejected_even_when_digest_is_signed():
    _, receipt, _, expected, spec, grid, keyring, private = fixture()
    raw = b'{"schema":"try.algorithm-artifact.v1","schema":"try.algorithm-artifact.v1"}'
    digest = hashlib.sha256(raw).hexdigest()
    malformed = dict(receipt, artifact_sha256=digest, output_sha256=digest)
    signed = {field: malformed[field] for field in SIGNED_FIELDS}
    malformed["signature"] = base64.b64encode(
        private.sign(canonical_json(signed).encode("utf-8"))
    ).decode("ascii")
    with pytest.raises(AlgorithmWorkerArtifactError, match="duplicate JSON keys"):
        verify_algorithm_worker_artifact(
            malformed, raw, expected=expected, grid=grid, spec=spec,
            expected_executor_revision="b" * 40, expected_executor_sha256="c" * 64,
            keyring=keyring,
        )
