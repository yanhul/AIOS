import base64
import hashlib
import json
from unittest.mock import patch

import pytest

from core.authority_bundle import AuthorityBundleError, verify_immutable_store_object


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\\0" + content).hexdigest()


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
