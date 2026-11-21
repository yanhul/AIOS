import hashlib

import pytest

from scripts.ingest_ci_evidence import verify_artifact_digest


def test_artifact_digest_matches_github_metadata():
    payload = b"trusted emulator log zip bytes"
    expected = hashlib.sha256(payload).hexdigest()
    assert verify_artifact_digest({"digest": f"sha256:{expected}"}, payload) == expected


def test_artifact_digest_rejects_missing_metadata():
    with pytest.raises(RuntimeError, match="no SHA-256 digest"):
        verify_artifact_digest({"name": "firestore-emulator-1"}, b"bytes")


def test_artifact_digest_rejects_malformed_metadata():
    with pytest.raises(RuntimeError, match="malformed"):
        verify_artifact_digest({"digest": "sha256:not-a-digest"}, b"bytes")


def test_artifact_digest_rejects_download_mismatch():
    payload = b"actual downloaded bytes"
    different = hashlib.sha256(b"different bytes").hexdigest()
    with pytest.raises(RuntimeError, match="do not match"):
        verify_artifact_digest({"digest": f"sha256:{different}"}, payload)
