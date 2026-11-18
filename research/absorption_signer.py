"""Isolated Ed25519 permit signer. Reads JSON evidence only; never executes candidate code."""
from __future__ import annotations
import hashlib, json, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from core.absorption_authority import sign_absorption_permit, _key_id, _public_hex

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def digest_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def run():
    required = ("AIOS_SOURCE_RUN_ID", "AIOS_SOURCE_COMMIT_SHA", "AIOS_TARGET_BRANCH",
                "GITHUB_REPOSITORY", "AIOS_ABSORPTION_PERMIT_PRIVATE_KEY")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError("missing signer inputs: " + ", ".join(missing) + "; DENY")
    repository = os.environ["GITHUB_REPOSITORY"]
    policy = read_json(os.environ.get("AIOS_POLICY_PATH", ROOT / "policies/absorption-default-deny.v1.json"))
    approval = read_json(os.environ.get("AIOS_APPROVAL_PATH", "input/approval.json"))
    governance_keyring = read_json(os.environ.get("AIOS_GOVERNANCE_KEYRING_PATH", ROOT / "policies/absorption-governance-keyring.json"))
    permit_keyring = read_json(os.environ.get("AIOS_PERMIT_KEYRING_PATH", ROOT / "policies/absorption-permit-keyring.json"))
    names = ("absorption-executor.json", "absorption-verification.json",
             "absorption-runtime-proof.json", "absorption-promotion.json")
    artifacts = {name: read_json(Path(os.environ.get("AIOS_ARTIFACTS_DIR", "input")) / name) for name in names}
    expected = {name: digest_json(value) for name, value in artifacts.items()}
    lineage = {"repository": repository, "run_id": os.environ["AIOS_SOURCE_RUN_ID"],
               "source_commit_sha": os.environ["AIOS_SOURCE_COMMIT_SHA"], "artifacts": expected}
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(os.environ["AIOS_ABSORPTION_PERMIT_PRIVATE_KEY"]))
    key_id = _key_id(_public_hex(private))
    entry = permit_keyring.get(key_id)
    if not isinstance(entry, dict) or entry.get("revoked") is not False:
        raise RuntimeError("signer public key is not present and active in the trusted permit keyring; DENY")
    permit = sign_absorption_permit(
        policy=policy, approval=approval, governance_keyring=governance_keyring,
        repository=repository, target_branch=os.environ["AIOS_TARGET_BRANCH"],
        lineage=lineage, expected_run_id=os.environ["AIOS_SOURCE_RUN_ID"],
        expected_commit_sha=os.environ["AIOS_SOURCE_COMMIT_SHA"],
        expected_artifacts=expected, permit_private_key=private,
    )
    out = Path(os.environ.get("AIOS_PERMIT_OUT", "output/absorption-permit.json"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(permit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"result": "SIGNED", "permit_key_id": permit["key_id"],
                      "source_run_id": permit["run_id"], "artifact_count": len(expected)}))
    return permit

if __name__ == "__main__":
    run()
