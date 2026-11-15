import base64
import hashlib
import json
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.authority_bundle import AuthorityBundleError, verify_immutable_store_object, verify_issuer_receipt


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


class Response:
    def __init__(self, value):
        self.value = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.value


def fixture():
    envelope = {"payload": {"store_commit": "a" * 40}, "signature": {"value": "test"}}
    content = (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode()
    blob_sha = git_blob_sha(content)
    commit_sha = "c" * 40
    parent_sha = "b" * 40
    path = "authority/issued/123-" + "d" * 40 + ".json"
    responses = {
        f"https://api.github.com/repos/yanhul/aios-authority-store/git/commits/{commit_sha}": {
            "parents": [{"sha": parent_sha}], "tree": {"sha": "e" * 40}
        },
        f"https://api.github.com/repos/yanhul/aios-authority-store/compare/{parent_sha}...{commit_sha}": {
            "status": "ahead", "ahead_by": 1, "total_commits": 1,
            "files": [{"filename": path, "status": "added"}]
        },
        f"https://api.github.com/repos/yanhul/aios-authority-store/git/trees/{'e' * 40}?recursive=1": {
            "truncated": False, "tree": [{"path": path, "type": "blob", "sha": blob_sha}]
        },
        f"https://api.github.com/repos/yanhul/aios-authority-store/git/blobs/{blob_sha}": {
            "encoding": "base64", "content": base64.b64encode(content).decode()
        },
    }
    return envelope, commit_sha, parent_sha, path, blob_sha, responses


def run(envelope, commit, parent, path, responses):
    def fake_urlopen(request, timeout=20):
        assert request.get_header("Authorization") == "Bearer test-token"
        return Response(responses[request.full_url])

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        return verify_immutable_store_object(
            envelope, repository="yanhul/aios-authority-store",
            bundle_commit=commit, signed_store_parent=parent,
            bundle_path=path, github_token="test-token",
        )


def test_verifies_actual_commit_parent_path_and_blob():
    envelope, commit, parent, path, blob_sha, responses = fixture()
    proof = run(envelope, commit, parent, path, responses)
    assert proof == {
        "repository": "yanhul/aios-authority-store",
        "signed_store_parent": parent,
        "bundle_commit": commit,
        "bundle_path": path,
        "bundle_blob_sha": blob_sha,
    }


def test_rejects_non_child_commit():
    envelope, commit, parent, path, responses = fixture()
    responses[next(k for k in responses if "/git/commits/" in k)]["parents"] = [{"sha": "f" * 40}]
    with pytest.raises(AuthorityBundleError, match="direct child"):
        run(envelope, commit, parent, path, responses)


def test_rejects_replaced_blob_content():
    envelope, commit, parent, path, responses = fixture()
    blob_key = next(k for k in responses if "/git/blobs/" in k)
    responses[blob_key]["content"] = base64.b64encode(b'{"tampered":true}').decode()
    with pytest.raises(AuthorityBundleError, match="blob hash mismatch"):
        run(envelope, commit, parent, path, responses)


def test_rejects_missing_exact_bundle_path():
    envelope, commit, parent, path, responses = fixture()
    tree_key = next(k for k in responses if "/git/trees/" in k)
    responses[tree_key]["tree"][0]["path"] = "authority/issued/other.json"
    with pytest.raises(AuthorityBundleError, match="path is missing"):
        run(envelope, commit, parent, path, responses)



def test_rejects_storage_commit_with_extra_changes():
    envelope, commit, parent, path, responses = fixture()
    compare_key = next(k for k in responses if "/compare/" in k)
    responses[compare_key]["files"].append({"filename": "README.md", "status": "modified"})
    with pytest.raises(AuthorityBundleError, match="only the exact issued bundle"):
        run(envelope, commit, parent, path, responses)


def test_rejects_multi_commit_storage_history():
    envelope, commit, parent, path, responses = fixture()
    compare_key = next(k for k in responses if "/compare/" in k)
    responses[compare_key]["ahead_by"] = 2
    responses[compare_key]["total_commits"] = 2
    with pytest.raises(AuthorityBundleError, match="only the exact issued bundle"):
        run(envelope, commit, parent, path, responses)


def test_verifies_issuer_signed_post_commit_receipt():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    bundle_commit, parent = "c" * 40, "b" * 40
    bundle_path = "authority/issued/712345-" + "a" * 40 + ".json"
    receipt_path = "authority/receipts/712345-" + "a" * 40 + ".json"
    receipt_commit, tree_sha = "d" * 40, "e" * 40
    bundle_blob_sha = "f" * 40
    payload = {
        "receipt_type": "AIOS_AUTHORITY_ISSUANCE_RECEIPT",
        "schema_version": 1,
        "issuer": "yanhul/aios-authority-store",
        "repository": "yanhul/aios-authority-store",
        "bundle_commit": bundle_commit,
        "bundle_path": bundle_path,
        "bundle_blob_sha": bundle_blob_sha,
        "signed_store_parent": parent,
        "source_run_id": 712345,
        "source_target_sha": "a" * 40,
        "issuer_workflow_run_id": 987654,
    }
    signed = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    envelope = {"payload": payload, "signature": {
        "algorithm": "Ed25519",
        "key_id": "ed25519:" + hashlib.sha256(bytes.fromhex(public)).hexdigest()[:32],
        "value": private.sign(signed).hex(),
    }}
    content = (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode()
    receipt_blob_sha = git_blob_sha(content)
    root = "https://api.github.com/repos/yanhul/aios-authority-store"
    responses = {
        f"{root}/git/commits/{receipt_commit}": {
            "parents": [{"sha": bundle_commit}], "tree": {"sha": tree_sha}
        },
        f"{root}/compare/{bundle_commit}...{receipt_commit}": {
            "status": "ahead", "ahead_by": 1, "total_commits": 1,
            "files": [{"filename": receipt_path, "status": "added"}]
        },
        f"{root}/git/trees/{tree_sha}?recursive=1": {
            "truncated": False, "tree": [{"path": receipt_path, "type": "blob", "sha": receipt_blob_sha}]
        },
        f"{root}/git/blobs/{receipt_blob_sha}": {
            "encoding": "base64", "content": base64.b64encode(content).decode()
        },
    }
    def fake_urlopen(request, timeout=20):
        assert request.get_header("Authorization") == "Bearer test-token"
        return Response(responses[request.full_url])
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        proof = verify_issuer_receipt(
            trusted_issuer="yanhul/aios-authority-store",
            trusted_public_key_hex=public,
            repository="yanhul/aios-authority-store",
            bundle_commit=bundle_commit,
            bundle_path=bundle_path,
            bundle_blob_sha=bundle_blob_sha,
            expected_store_parent=parent,
            expected_source_run_id=712345,
            expected_source_target_sha="a" * 40,
            receipt_commit=receipt_commit,
            receipt_path=receipt_path,
            github_token="test-token",
        )
    assert proof["receipt_commit"] == receipt_commit
    assert proof["bundle_blob_sha"] == bundle_blob_sha

