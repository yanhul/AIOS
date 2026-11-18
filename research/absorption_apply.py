"""Materialize only same-run records with independently revalidated signed lineage."""
from __future__ import annotations
import hashlib, json, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from core.evidence import verify_evidence
from core.absorption_effect_guard import authorize_absorption_effect

DEFAULT_EXEC = ROOT / "research/artifacts/absorption-executor.json"
DEFAULT_VERIFY = ROOT / "research/artifacts/absorption-verification.json"
DEFAULT_PROMO = ROOT / "research/artifacts/absorption-promotion.json"
DEFAULT_RUNTIME = ROOT / "research/artifacts/absorption-runtime-proof.json"
DEFAULT_OUT = ROOT / "research/artifacts/absorption.json"


def _path(name, default):
    return Path(os.environ.get(name, str(default)))


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _verification_digest_valid(verification):
    expected = _digest({"verified": verification.get("records", []),
                        "failures": verification.get("failures", [])})
    return verification.get("digest") == expected


def _runtime_digest_valid(runtime):
    if not isinstance(runtime.get("implementation"), dict) or not isinstance(runtime.get("probes"), dict):
        return False
    digest = _digest({"implementation": runtime["implementation"], "probes": runtime["probes"]})
    return runtime.get("digest") == digest


def _promotion_digest_valid(promotion):
    unsigned = dict(promotion)
    supplied = unsigned.pop("digest", None)
    attestation = unsigned.pop("attestation", None)
    return isinstance(supplied, str) and supplied == _digest(unsigned)


def _authorize_absorption_effect(artifacts, *, run_id, effect):
    def required_path(env_name):
        value = os.environ.get(env_name)
        if not value:
            raise RuntimeError(f"{env_name} is required; DENY")
        return Path(value)
    policy_path = Path(os.environ.get("AIOS_ABSORPTION_POLICY_PATH", ROOT / "policies/absorption-default-deny.v1.json"))
    permit_path = required_path("AIOS_ABSORPTION_PERMIT_PATH")
    keyring_path = required_path("AIOS_ABSORPTION_PERMIT_KEYRING_PATH")
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    permit = json.loads(permit_path.read_text(encoding="utf-8"))
    keyring = json.loads(keyring_path.read_text(encoding="utf-8"))
    digests = {
        "absorption-executor.json": _digest(artifacts["executor"]),
        "absorption-verification.json": _digest(artifacts["verification"]),
        "absorption-promotion.json": _digest(artifacts["promotion"]),
        "absorption-runtime-proof.json": _digest(artifacts["runtime"]),
    }
    return authorize_absorption_effect(
        permit=permit, permit_keyring=keyring, policy=policy,
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
        target_branch=os.environ.get("AIOS_TARGET_BRANCH", ""),
        run_id=run_id, source_commit_sha=os.environ.get("AIOS_SOURCE_COMMIT_SHA", os.environ.get("GITHUB_SHA", "")),
        artifact_digests=digests,
        target_apply_run_id=os.environ.get("AIOS_TARGET_APPLY_RUN_ID", os.environ.get("GITHUB_RUN_ID", "")), effect=effect,
    )


def absorb(executor, verification, promotion, runtime, *, run_id):
    if not run_id:
        raise RuntimeError("current run_id is required for absorption")
    artifacts = {"executor": executor, "verification": verification,
                 "promotion": promotion, "runtime": runtime}
    for name, artifact in artifacts.items():
        if artifact.get("run_id") != run_id:
            raise RuntimeError(f"{name} artifact run_id does not match current run")
    if any(r.get("run_id") != run_id for r in executor.get("records", [])):
        raise RuntimeError("executor contains stale candidate records")
    if any(r.get("run_id") != run_id for r in verification.get("records", [])):
        raise RuntimeError("verification contains stale evidence records")
    if verification.get("overall") != "PASS":
        raise RuntimeError("cannot materialize without current-run independent verification PASS")
    if not _verification_digest_valid(verification):
        raise RuntimeError("verification artifact content digest mismatch")
    if runtime.get("overall") != "PASS" or not _runtime_digest_valid(runtime):
        raise RuntimeError("runtime proof is not PASS or its content digest is invalid")
    if promotion.get("overall") != "PASS" or not _promotion_digest_valid(promotion):
        raise RuntimeError("promotion is not PASS or its content digest is invalid")
    if promotion.get("input_verification_digest") != verification.get("digest"):
        raise RuntimeError("promotion is not bound to this verification artifact")
    if promotion.get("input_runtime_digest") != runtime.get("digest"):
        raise RuntimeError("promotion is not bound to this runtime proof")
    exec_by_id = {r.get("candidate_id"): r for r in executor.get("records", [])}
    verified = {r.get("candidate_id"): r for r in verification.get("records", [])}
    decisions = [d for d in promotion.get("decisions", [])
                 if d.get("allowed") is True and d.get("verdict") == "PROMOTE" and d.get("run_id") == run_id]
    records, blocked = [], []
    authorization_error = None
    if decisions:
        try:
            _authorize_absorption_effect(artifacts, run_id=run_id,
                                         effect="materialize_absorbed_registry")
        except Exception as exc:
            authorization_error = "apply-time Ed25519 permit enforcement denied effect: " + str(exc)
    for decision in decisions:
        cid = decision.get("candidate_id")
        if authorization_error:
            blocked.append({"candidate_id": cid, "verdict": "HOLD", "reason": authorization_error})
            continue
        source = exec_by_id.get(cid)
        evidence = verified.get(cid)
        if not source or not evidence:
            blocked.append({"candidate_id": cid, "verdict": "HOLD",
                            "reason": "missing same-run executor or verification lineage"})
            continue
        if source.get("run_id") != evidence.get("run_id") or evidence.get("run_id") != run_id:
            blocked.append({"candidate_id": cid, "verdict": "HOLD", "reason": "candidate lineage run_id mismatch"})
            continue
        if (source.get("source_ref") != evidence.get("source_ref") or
                source.get("source_digest") != evidence.get("source_digest") or
                source.get("evidence_digest") != evidence.get("evidence_digest") or
                evidence.get("candidate_digest") != _digest(source) or
                evidence.get("test_digest") != verification.get("independent_tests", {}).get("digest")):
            blocked.append({"candidate_id": cid, "verdict": "HOLD",
                            "reason": "source/evidence/test digest chain mismatch"})
            continue
        if evidence.get("level") not in {"VERIFIED_DIGITAL", "PROMOTED"} or not verify_evidence(evidence):
            blocked.append({"candidate_id": cid, "verdict": "HOLD",
                            "reason": "apply-time evidence digest/level validation failed"})
            continue
        records.append({"candidate_id": cid, "run_id": run_id, "source_ref": source["source_ref"],
            "source_digest": source["source_digest"], "evidence_digest": source["evidence_digest"],
            "test_digest": evidence["test_digest"], "candidate_digest": evidence["candidate_digest"], "evidence_record_digest": evidence["digest"],
            "claim": evidence["claim"],
            "primitive": source["adaptation"]["primitive"], "signals": source["adaptation"]["signals"],
            "proposal": source["adaptation"]["proposal"], "target_surface": source["adaptation"]["target_surface"],
            "absorption_kind": "AIOS_NATIVE_PRIMITIVE_REGISTRY", "status": "ABSORBED",
            "implementation_status": "IMPLEMENTED_AND_CONFORMANT", "runtime_status": "PROVEN",
            "external_code_copy": False, "external_code_execution": False, "source_mutation": False,
            "authority": "AIOS_CONTROL_PLANE", "verification": "INDEPENDENT_STRUCTURAL_CONFORMANCE",
            "runtime_proof": runtime.get("digest")})
    expected = len(promotion.get("decisions", [])) + len(promotion.get("blocked", []))
    result = {"schema_version": 4, "kind": "AIOS_ABSORPTION", "run_id": run_id,
        "candidate_count": expected, "absorbed_count": len(records),
        "deferred_count": expected - len(records), "records": records,
        "blocked": blocked + [{"candidate_id": x.get("candidate_id"), "verdict": "DEFER",
            "reason": x.get("reason", "promotion gate blocked")} for x in promotion.get("blocked", [])],
        "overall": "PASS" if expected and len(records) == expected and not blocked and not promotion.get("blocked")
                   else "PASS_WITH_HOLDS" if records else "BLOCKED",
        "source_mutation": False, "external_code_execution": False,
        "authority": "AIOS_CONTROL_PLANE", "implementation_runtime_proof": "PASS"}
    out = _path("AIOS_ABSORPTION_OUTCOME", DEFAULT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    e = json.loads(_path("AIOS_ABSORPTION_EXECUTOR_IN", DEFAULT_EXEC).read_text())
    v = json.loads(_path("AIOS_ABSORPTION_VERIFY_IN", DEFAULT_VERIFY).read_text())
    p = json.loads(_path("AIOS_ABSORPTION_PROMO_IN", DEFAULT_PROMO).read_text())
    r = json.loads(_path("AIOS_ABSORPTION_RUNTIME_IN", DEFAULT_RUNTIME).read_text())
    result = absorb(e, v, p, r, run_id=os.environ.get("AIOS_SOURCE_RUN_ID", os.environ.get("GITHUB_RUN_ID", "")))
    raise SystemExit(0 if result["overall"] in {"PASS", "PASS_WITH_HOLDS"} else 1)
