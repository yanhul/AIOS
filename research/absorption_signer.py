"""Isolated Ed25519 permit signer. Reads JSON evidence only; never executes candidate code."""
from __future__ import annotations
import hashlib, json, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from core.absorption_authority import (sign_absorption_permit, verify_approval_attestation,
                                       _key_id, _public_hex)

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def digest_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def validate_artifact_bundle(artifacts, *, source_run_id):
    """Validate artifact semantics before the permit key is loaded."""
    required = {"absorption-executor.json", "absorption-verification.json",
                "absorption-runtime-proof.json", "absorption-promotion.json"}
    if set(artifacts) != required:
        raise RuntimeError("signer artifact set mismatch; DENY")
    executor = artifacts["absorption-executor.json"]
    verification = artifacts["absorption-verification.json"]
    runtime = artifacts["absorption-runtime-proof.json"]
    promotion = artifacts["absorption-promotion.json"]
    for name, artifact in artifacts.items():
        if not isinstance(artifact, dict) or artifact.get("run_id") != source_run_id:
            raise RuntimeError(f"{name} source run binding mismatch; DENY")
    if executor.get("kind") != "AIOS_ABSORPTION_EXECUTOR" or executor.get("overall") != "PASS":
        raise RuntimeError("executor artifact is not a PASS result; DENY")
    if verification.get("kind") != "AIOS_ABSORPTION_INDEPENDENT_VERIFICATION" or verification.get("overall") != "PASS":
        raise RuntimeError("verification artifact is not a PASS result; DENY")
    if verification.get("digest") != digest_json({
        "verified": verification.get("records", []),
        "failures": verification.get("failures", []),
    }):
        raise RuntimeError("verification artifact digest mismatch; DENY")
    tests = verification.get("independent_tests")
    if not isinstance(tests, dict) or tests.get("passed") is not True:
        raise RuntimeError("independent tests did not PASS; DENY")
    if runtime.get("kind") != "AIOS_ABSORPTION_RUNTIME_PROOF" or runtime.get("overall") != "PASS":
        raise RuntimeError("runtime proof is not a PASS result; DENY")
    implementation, probes = runtime.get("implementation"), runtime.get("probes")
    if not isinstance(implementation, dict) or implementation.get("overall") != "PASS":
        raise RuntimeError("implementation conformance is not PASS; DENY")
    if not isinstance(probes, dict) or not probes or any(value is not True for value in probes.values()):
        raise RuntimeError("runtime proof contains failed or missing probes; DENY")
    if runtime.get("digest") != digest_json({"implementation": implementation, "probes": probes}):
        raise RuntimeError("runtime proof digest mismatch; DENY")
    if promotion.get("kind") != "AIOS_ABSORPTION_PROMOTION" or promotion.get("overall") != "PASS":
        raise RuntimeError("promotion artifact is not a PASS result; DENY")
    unsigned_promotion = dict(promotion)
    supplied_promotion_digest = unsigned_promotion.pop("digest", None)
    unsigned_promotion.pop("attestation", None)
    if supplied_promotion_digest != digest_json(unsigned_promotion):
        raise RuntimeError("promotion artifact digest mismatch; DENY")
    if promotion.get("input_verification_digest") != verification.get("digest"):
        raise RuntimeError("promotion is not bound to verification artifact; DENY")
    if promotion.get("input_runtime_digest") != runtime.get("digest"):
        raise RuntimeError("promotion is not bound to runtime proof; DENY")
    if promotion.get("blocked") or not promotion.get("decisions"):
        raise RuntimeError("promotion has holds or no approved decisions; DENY")
    executor_ids = {r.get("candidate_id") for r in executor.get("records", [])}
    verified_ids = {r.get("candidate_id") for r in verification.get("records", [])}
    promoted_ids = {r.get("candidate_id") for r in promotion.get("decisions", [])
                    if r.get("allowed") is True and r.get("verdict") == "PROMOTE"
                    and r.get("run_id") == source_run_id}
    if not executor_ids or executor_ids != verified_ids or executor_ids != promoted_ids:
        raise RuntimeError("executor/verification/promotion candidate sets differ; DENY")
    if any(r.get("run_id") != source_run_id for r in executor.get("records", []) + verification.get("records", [])):
        raise RuntimeError("candidate record lineage mismatch; DENY")
    if any(
        (r.get("adaptation") or {}).get("external_code_copy", r.get("external_code_copy")) is not False or
        (r.get("adaptation") or {}).get("external_code_execution", r.get("external_code_execution")) is not False
        for r in executor.get("records", [])
    ):
        raise RuntimeError("executor record permits external code copy/execution; DENY")
    return True


def run():
    required = ("AIOS_SOURCE_RUN_ID", "AIOS_SOURCE_COMMIT_SHA", "AIOS_TARGET_BRANCH", "AIOS_TARGET_APPLY_RUN_ID",
                "GITHUB_REPOSITORY", "AIOS_ABSORPTION_PERMIT_PRIVATE_KEY")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError("missing signer inputs: " + ", ".join(missing) + "; DENY")
    repository = os.environ["GITHUB_REPOSITORY"]
    policy = read_json(os.environ.get("AIOS_POLICY_PATH", ROOT / "policies/absorption-default-deny.v1.json"))
    approval = read_json(os.environ.get("AIOS_APPROVAL_PATH", ROOT / "policies/absorption-approval.json"))
    governance_keyring = read_json(os.environ.get("AIOS_GOVERNANCE_KEYRING_PATH", ROOT / "policies/absorption-governance-keyring.json"))
    permit_keyring = read_json(os.environ.get("AIOS_PERMIT_KEYRING_PATH", ROOT / "policies/absorption-permit-keyring.json"))
    names = ("absorption-executor.json", "absorption-verification.json",
             "absorption-runtime-proof.json", "absorption-promotion.json")
    artifacts = {name: read_json(Path(os.environ.get("AIOS_ARTIFACTS_DIR", "input")) / name) for name in names}
    validate_artifact_bundle(artifacts, source_run_id=os.environ["AIOS_SOURCE_RUN_ID"])
    verify_approval_attestation(
        policy=policy, approval=approval, governance_keyring=governance_keyring,
        repository=repository, target_branch=os.environ["AIOS_TARGET_BRANCH"],
    )
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
        expected_artifacts=expected, target_apply_run_id=os.environ["AIOS_TARGET_APPLY_RUN_ID"],
        permit_private_key=private,
    )
    out = Path(os.environ.get("AIOS_PERMIT_OUT", "output/absorption-permit.json"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(permit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"result": "SIGNED", "permit_key_id": permit["key_id"],
                      "source_run_id": permit["run_id"], "target_apply_run_id": permit["target_apply_run_id"],
                      "artifact_count": len(expected)}))
    return permit

if __name__ == "__main__":
    run()
