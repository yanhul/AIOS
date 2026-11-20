"""Durable capability candidate, evaluation, promotion and rollback records (M11).

All records are append-only and committed with their audit event through the
shared mutation kernel. A candidate never activates itself: promotion requires
a PASS evaluation by an evaluator distinct from the proposer, independently
resolvable evidence, a third-party approver, and an explicit authority callback.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from typing import Any

from .mutation import MutationError, TransitionError, _require_actor, canonical_json, commit_batch, event_identity

__all__ = [
    "CapabilityEvolutionError",
    "propose_candidate",
    "load_candidates",
    "evaluate_candidate",
    "load_evaluations",
    "promote_candidate",
    "rollback_capability",
    "load_decisions",
    "active_version",
]

_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")


class CapabilityEvolutionError(MutationError):
    """Invalid candidate or capability-version transition."""


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CapabilityEvolutionError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(value: Any, name: str, *, commit: bool = False) -> str:
    raw = _required(value, name).lower()
    if not (_COMMIT if commit else _SHA).fullmatch(raw):
        raise CapabilityEvolutionError(f"{name} has invalid {'commit' if commit else 'SHA-256'} digest")
    return raw


def _refs(values: Any) -> list[str]:
    if not isinstance(values, list) or not values:
        raise CapabilityEvolutionError("evidence_refs must be a non-empty list")
    refs = [_required(value, "evidence_ref") for value in values]
    if len(set(refs)) != len(refs):
        raise CapabilityEvolutionError("evidence_refs must be unique")
    return sorted(refs)


def _semver(value: Any, name: str) -> tuple[str, tuple[int, int, int]]:
    raw = _required(value, name)
    match = _SEMVER.fullmatch(raw)
    if not match:
        raise CapabilityEvolutionError(f"{name} must use MAJOR.MINOR.PATCH")
    return raw, tuple(int(part) for part in match.groups())


def _identity(record: Mapping[str, Any]) -> str:
    logical = {k: v for k, v in record.items() if k not in {"created_at", "record_id", "identity"}}
    return hashlib.sha256(canonical_json(logical).encode("utf-8")).hexdigest()


def _event(record: Mapping[str, Any], actor: str, action: str) -> dict[str, Any]:
    return {
        "kind": "mutation",
        "action": action,
        "actor": actor,
        "record_type": record["record_type"],
        "record_id": record["record_id"],
        "record_identity": record["identity"],
        "capability_id": record["capability_id"],
        "candidate_id": record.get("candidate_id"),
        "decision": record.get("decision"),
        "verdict": record.get("verdict"),
        "from_version": record.get("from_version"),
        "to_version": record.get("to_version"),
    }


def _persist(aios_dir: str, folder: str, record: dict[str, Any], actor: str, action: str) -> dict[str, Any]:
    _require_actor(actor)
    relative = os.path.join(folder, record["record_id"] + ".json")
    destination = os.path.join(aios_dir, relative)
    if os.path.exists(destination):
        with open(destination, "r", encoding="utf-8") as fh:
            existing = json.load(fh)
        existing_logical = {k: value for k, value in existing.items() if k != "created_at"}
        record_logical = {k: value for k, value in record.items() if k != "created_at"}
        if canonical_json(existing_logical) != canonical_json(record_logical):
            raise TransitionError(f"immutable identity collision: {record['record_id']}")
        _require_event(aios_dir, record, action)
        return {"record_id": record["record_id"], "replayed": True}

    event = _event(record, actor, action)
    event_id = event_identity(event)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    event_relative = os.path.join("events", f"EVT-{stamp}-{event_id}.json")
    event_record = {
        **event,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds"),
        "event_id": event_id,
    }

    def precondition(root: str) -> None:
        if os.path.exists(os.path.join(root, relative)):
            raise TransitionError("concurrent append detected; reload capability evolution state")

    commit_batch(aios_dir, [(relative, record), (event_relative, event_record)], precondition=precondition)
    return {"record_id": record["record_id"], "replayed": False, "event_file": os.path.basename(event_relative)}


def _require_event(aios_dir: str, record: Mapping[str, Any], action: str | None = None) -> None:
    root = os.path.join(aios_dir, "events")
    for filename in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        if not filename.endswith(".json"):
            continue
        try:
            with open(os.path.join(root, filename), "r", encoding="utf-8") as fh:
                stored = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if stored.get("record_id") != record.get("record_id"):
            continue
        logical = {k: v for k, v in stored.items() if k not in {"timestamp_utc", "event_id"}}
        event_action = logical.get("action")
        if action is not None and event_action != action:
            continue
        event_id = stored.get("event_id")
        if not isinstance(event_id, str) or event_identity(logical) != event_id:
            continue
        if filename != f"EVT-{filename.split('-', 2)[1]}-{event_id}.json":
            continue
        if logical != _event(record, stored.get("actor"), event_action):
            continue
        return
    raise TransitionError(f"{record.get('record_type')} {record.get('record_id')} has no integrity-bound audit event")


def _load(aios_dir: str, folder: str, prefix: str, kind: str) -> dict[str, dict[str, Any]]:
    root = os.path.join(aios_dir, folder)
    out: dict[str, dict[str, Any]] = {}
    if not os.path.isdir(root):
        return out
    for filename in sorted(os.listdir(root)):
        if not filename.endswith(".json"):
            continue
        try:
            with open(os.path.join(root, filename), "r", encoding="utf-8") as fh:
                record = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise TransitionError(f"invalid persisted {kind} record {filename!r}") from exc
        if not isinstance(record, dict) or record.get("record_type") != kind:
            raise TransitionError(f"invalid persisted {kind} record {filename!r}")
        identity = record.get("identity")
        record_id = record.get("record_id")
        if not isinstance(identity, str) or identity != _identity(record) or record_id != prefix + identity:
            raise TransitionError(f"{kind} record {filename!r} has invalid identity")
        if filename != record_id + ".json" or record_id in out:
            raise TransitionError(f"duplicate or non-canonical {kind} identity {record_id!r}")
        _require_event(aios_dir, record)
        out[record_id] = record
    return out


def _seal(record: dict[str, Any], prefix: str) -> dict[str, Any]:
    identity = _identity(record)
    record.update({
        "record_id": prefix + identity,
        "identity": identity,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds"),
    })
    return record


def propose_candidate(
    aios_dir: str, *, capability_id: str, base_version: str,
    candidate_version: str, proposer: str, source_commit: str,
    patch_digest: str, change_summary: str, evidence_refs: list[str],
    run_id: str, actor: str,
) -> dict[str, Any]:
    """Persist a candidate patch reference; does not change the active version."""
    _require_actor(actor)
    capability_id = _required(capability_id, "capability_id")
    base_version, base_tuple = _semver(base_version, "base_version")
    candidate_version, candidate_tuple = _semver(candidate_version, "candidate_version")
    if candidate_tuple <= base_tuple:
        raise CapabilityEvolutionError("candidate version must be greater than its base")
    proposer = _required(proposer, "proposer")
    source_commit = _digest(source_commit, "source_commit", commit=True)
    patch_digest = _digest(patch_digest, "patch_digest")
    change_summary = _required(change_summary, "change_summary")
    refs = _refs(evidence_refs)
    run_id = _required(run_id, "run_id")
    record = _seal({
        "record_type": "CAPABILITY_CANDIDATE",
        "capability_id": capability_id,
        "base_version": base_version,
        "candidate_version": candidate_version,
        "proposer": proposer,
        "source_commit": source_commit,
        "patch_digest": patch_digest,
        "change_summary": change_summary,
        "evidence_refs": refs,
        "run_id": run_id,
    }, "CV-")
    result = _persist(aios_dir, "capability_candidates", record, actor, "capability.candidate_proposed")
    return {**result, "candidate_id": record["record_id"], "status": "CANDIDATE"}


def load_candidates(aios_dir: str) -> dict[str, dict[str, Any]]:
    return _load(aios_dir, "capability_candidates", "CV-", "CAPABILITY_CANDIDATE")


def evaluate_candidate(
    aios_dir: str, *, candidate_id: str, evaluator: str,
    evaluator_version: str, verdict: str, test_suite_digest: str,
    comparison_digest: str, evidence_refs: list[str], run_id: str,
    actor: str,
) -> dict[str, Any]:
    """Append an evaluation by an identity distinct from the candidate proposer."""
    _require_actor(actor)
    candidate_id = _required(candidate_id, "candidate_id")
    candidate = load_candidates(aios_dir).get(candidate_id)
    if candidate is None:
        raise CapabilityEvolutionError(f"unknown candidate {candidate_id}")
    evaluator = _required(evaluator, "evaluator")
    if evaluator == candidate["proposer"]:
        raise CapabilityEvolutionError("candidate proposer cannot evaluate their own candidate")
    evaluator_version = _required(evaluator_version, "evaluator_version")
    if verdict not in {"PASS", "FAIL", "INCONCLUSIVE"}:
        raise CapabilityEvolutionError("verdict must be PASS, FAIL or INCONCLUSIVE")
    record = _seal({
        "record_type": "CAPABILITY_EVALUATION",
        "candidate_id": candidate_id,
        "capability_id": candidate["capability_id"],
        "evaluator": evaluator,
        "evaluator_version": evaluator_version,
        "verdict": verdict,
        "test_suite_digest": _digest(test_suite_digest, "test_suite_digest"),
        "comparison_digest": _digest(comparison_digest, "comparison_digest"),
        "evidence_refs": _refs(evidence_refs),
        "run_id": _required(run_id, "run_id"),
    }, "CE-")
    result = _persist(aios_dir, "capability_evaluations", record, actor, "capability.candidate_evaluated")
    return {**result, "evaluation_id": record["record_id"], "verdict": verdict}


def load_evaluations(aios_dir: str) -> dict[str, dict[str, Any]]:
    return _load(aios_dir, "capability_evaluations", "CE-", "CAPABILITY_EVALUATION")


def load_decisions(aios_dir: str) -> dict[str, dict[str, Any]]:
    return _load(aios_dir, "capability_decisions", "CD-", "CAPABILITY_DECISION")


def active_version(aios_dir: str, capability_id: str, default_version: str | None = None) -> str | None:
    decisions = [r for r in load_decisions(aios_dir).values() if r["capability_id"] == capability_id]
    if not decisions:
        return default_version
    decisions.sort(key=lambda r: (r["created_at"], r["record_id"]))
    return decisions[-1]["to_version"]


def _latest_evaluation(aios_dir: str, candidate_id: str) -> dict[str, Any]:
    records = [r for r in load_evaluations(aios_dir).values() if r["candidate_id"] == candidate_id]
    if not records:
        raise CapabilityEvolutionError("candidate has no independent evaluation")
    records.sort(key=lambda r: (r["created_at"], r["record_id"]))
    return records[-1]


def _append_decision(aios_dir: str, record: dict[str, Any], actor: str, action: str) -> dict[str, Any]:
    record = _seal(record, "CD-")
    result = _persist(aios_dir, "capability_decisions", record, actor, action)
    return {**result, "decision_id": record["record_id"], "status": record["decision"]}


def promote_candidate(
    aios_dir: str, *, candidate_id: str, approver: str,
    evidence_verifier: Callable[[list[str]], bool],
    promotion_authorizer: Callable[[Mapping[str, Any], Mapping[str, Any], str], bool],
) -> dict[str, Any]:
    """Promote only with three distinct actors, verified evidence and authority."""
    approver = _required(approver, "approver")
    candidate = load_candidates(aios_dir).get(_required(candidate_id, "candidate_id"))
    if candidate is None:
        raise CapabilityEvolutionError("unknown capability candidate")
    evaluation = _latest_evaluation(aios_dir, candidate["record_id"])
    if evaluation["verdict"] != "PASS":
        raise CapabilityEvolutionError("latest candidate evaluation is not PASS")
    if len({candidate["proposer"], evaluation["evaluator"], approver}) != 3:
        raise CapabilityEvolutionError("proposer, evaluator and approver must be three distinct identities")
    if not callable(evidence_verifier) or not callable(promotion_authorizer):
        raise CapabilityEvolutionError("independent evidence verifier and promotion authorizer are required")
    refs = sorted(set(candidate["evidence_refs"] + evaluation["evidence_refs"]))
    if evidence_verifier(refs) is not True:
        raise CapabilityEvolutionError("candidate evidence is not independently verified")
    if promotion_authorizer(candidate, evaluation, approver) is not True:
        raise PermissionError("AIOS authority denied capability promotion")
    current = active_version(aios_dir, candidate["capability_id"], candidate["base_version"])
    if current != candidate["base_version"]:
        raise CapabilityEvolutionError(f"candidate base is stale: active={current!r}, base={candidate['base_version']!r}")
    return _append_decision(aios_dir, {
        "record_type": "CAPABILITY_DECISION",
        "decision": "PROMOTED",
        "capability_id": candidate["capability_id"],
        "from_version": candidate["base_version"],
        "to_version": candidate["candidate_version"],
        "candidate_id": candidate["record_id"],
        "evaluation_id": evaluation["record_id"],
        "approver": approver,
        "evidence_refs": refs,
    }, approver, "capability.version_promoted")


def rollback_capability(
    aios_dir: str, *, capability_id: str, target_version: str,
    approver: str, evidence_verifier: Callable[[list[str]], bool],
    rollback_authorizer: Callable[[str, str, str], bool],
) -> dict[str, Any]:
    """Append an authorized rollback to a version present in prior history."""
    capability_id = _required(capability_id, "capability_id")
    target_version, _ = _semver(target_version, "target_version")
    approver = _required(approver, "approver")
    decisions = [r for r in load_decisions(aios_dir).values() if r["capability_id"] == capability_id]
    if not decisions:
        raise CapabilityEvolutionError("cannot rollback without promotion history")
    decisions.sort(key=lambda r: (r["created_at"], r["record_id"]))
    current = decisions[-1]["to_version"]
    prior_versions = {r["from_version"] for r in decisions} | {r["to_version"] for r in decisions}
    if target_version == current or target_version not in prior_versions:
        raise CapabilityEvolutionError("rollback target must be a different previously active version")
    refs = sorted({ref for r in decisions for ref in r["evidence_refs"]})
    if not callable(evidence_verifier) or not callable(rollback_authorizer):
        raise CapabilityEvolutionError("independent evidence verifier and rollback authorizer are required")
    if evidence_verifier(refs) is not True:
        raise CapabilityEvolutionError("rollback evidence is not independently verified")
    if rollback_authorizer(capability_id, current, target_version) is not True:
        raise PermissionError("AIOS authority denied capability rollback")
    return _append_decision(aios_dir, {
        "record_type": "CAPABILITY_DECISION",
        "decision": "ROLLED_BACK",
        "capability_id": capability_id,
        "from_version": current,
        "to_version": target_version,
        "candidate_id": None,
        "evaluation_id": None,
        "approver": approver,
        "evidence_refs": refs,
    }, approver, "capability.version_rolled_back")
