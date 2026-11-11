"""Detection-only audit of external-effect authority records.

This module is deliberately independent of effect_authority loaders: those
loaders may recover pending journals. The audit performs filesystem reads
only and never repairs, deletes, recovers, or changes an authority state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

from .mutation import canonical_json
from .record_seal import SealError, require_seal, unsealed_body

_EFFECT_RE = re.compile(r"EF-[0-9a-f]{64}\Z")
_RECEIPT_RE = re.compile(r"RC-[0-9a-f]{64}\Z")


def _read(path):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            return json.load(stream), None
    except FileNotFoundError:
        return None, "missing"
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _files(root, add, label):
    if not os.path.isdir(root):
        return []
    result = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not name.endswith(".json"):
            add(f"effect_audit.{label}.unexpected_file", "INCONSISTENT", path)
            continue
        if not os.path.isfile(path):
            add(f"effect_audit.{label}.unexpected_entry", "INCONSISTENT", path)
            continue
        obj, error = _read(path)
        if error:
            add(f"effect_audit.{label}.unreadable", "CORRUPTED", f"{path}: {error}")
            continue
        if not isinstance(obj, dict):
            add(f"effect_audit.{label}.schema", "CORRUPTED", f"{path}: record is not an object")
            continue
        result.append((name, path, obj))
    return result


def _check_seal(record, path, add):
    try:
        require_seal(record, os.path.basename(path))
    except SealError as exc:
        # Missing deployment key is an inability to verify, not proof that
        # the record is forged. A present but invalid seal is corruption.
        message = str(exc)
        severity = "UNSUPPORTED" if "AIOS_RECORD_SEAL_SECRET" in message else "CORRUPTED"
        add("effect_audit.seal.invalid_or_unverifiable", severity, f"{path}: {message}")


def audit_effect_authority(aios_dir, add):
    """Append findings for effects, receipts, reconciliations, evaluations,
    execution claims and external-effect events. No state is mutated.
    """
    effects = {}
    for name, path, rec in _files(os.path.join(aios_dir, "effects"), add, "effects"):
        eid = rec.get("effect_id")
        required = ("contract_id", "logical_operation_id", "permit_id", "actor", "effect_type",
                    "policy_digest", "max_attempts", "state", "attempt")
        missing = [field for field in required if field not in rec]
        if rec.get("record_type") != "EXTERNAL_EFFECT" or not isinstance(eid, str) or not _EFFECT_RE.fullmatch(eid) or missing:
            add("effect_audit.effects.schema", "CORRUPTED", f"{path}: invalid record_type/effect_id or missing {missing}")
            continue
        for field in ("contract_id", "logical_operation_id", "permit_id", "actor", "effect_type", "policy_digest"):
            if not isinstance(rec.get(field), str) or not rec[field].strip():
                add("effect_audit.effects.schema", "CORRUPTED", f"{path}: {field} must be a non-empty string")
        if isinstance(rec.get("max_attempts"), bool) or not isinstance(rec.get("max_attempts"), int) or rec["max_attempts"] < 1:
            add("effect_audit.effects.max_attempts", "CORRUPTED", f"{path}: max_attempts must be a positive integer")
        identity = {"contract_id": rec.get("contract_id"),
                    "logical_operation_id": rec.get("logical_operation_id"),
                    "actor": rec.get("actor")}
        expected_eid = "EF-" + hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
        if eid != expected_eid:
            add("effect_audit.effects.identity", "CORRUPTED", f"{path}: effect_id does not match contract/logical_operation/actor")
        if rec.get("state") not in ("PLANNED", "DISPATCHED", "UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
            add("effect_audit.effects.state", "CORRUPTED", f"{path}: invalid state")
        attempt = rec.get("attempt")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
            add("effect_audit.effects.attempt", "CORRUPTED", f"{path}: invalid attempt")
        if rec.get("state") == "PLANNED" and (attempt != 0 or "attempt_id" in rec or "provider" in rec):
            add("effect_audit.effects.planned_binding", "CORRUPTED", f"{path}: PLANNED effect carries attempt/provider")
        if rec.get("state") != "PLANNED":
            if attempt < 1 or rec.get("attempt_id") != f"{eid}:attempt:{attempt}":
                add("effect_audit.effects.attempt_binding", "CORRUPTED", f"{path}: attempt_id/attempt is not a positive derived identity")
            if not isinstance(rec.get("provider"), str) or not rec.get("provider", "").strip():
                add("effect_audit.effects.provider", "CORRUPTED", f"{path}: dispatched effect has no provider")
        if attempt > rec.get("max_attempts", 0):
            add("effect_audit.effects.attempt_budget", "CORRUPTED", f"{path}: attempt exceeds max_attempts")
        if name != eid + ".json":
            add("effect_audit.effects.path_binding", "CORRUPTED", f"{path}: filename does not bind effect_id")
        if eid in effects:
            add("effect_audit.effects.duplicate", "INCONSISTENT", f"duplicate effect_id {eid}")
        effects[eid] = rec

    receipts = {}
    for name, path, rec in _files(os.path.join(aios_dir, "receipts"), add, "receipts"):
        _check_seal(rec, path, add)
        rid, eid = rec.get("receipt_id"), rec.get("effect_id")
        required = ("attempt_id", "attempt", "contract_id", "provider", "provider_operation_id",
                    "outcome", "evidence", "recorded_via")
        missing = [field for field in required if field not in rec]
        if rec.get("record_type") != "PROVIDER_RECEIPT" or missing or not isinstance(rid, str) or not _RECEIPT_RE.fullmatch(rid):
            add("effect_audit.receipts.schema", "CORRUPTED", f"{path}: invalid type/id or missing {missing}")
            continue
        body = unsealed_body(rec)
        try:
            from .effect_authority import receipt_id_for
            expected = receipt_id_for(body)
            if expected != rid:
                add("effect_audit.receipts.identity", "CORRUPTED", f"{path}: receipt_id does not match content")
        except (TypeError, ValueError) as exc:
            add("effect_audit.receipts.identity", "CORRUPTED", f"{path}: {exc}")
        evidence = rec.get("evidence")
        from .evidence import verify_evidence
        if not isinstance(evidence, dict) or not verify_evidence(evidence):
            add("effect_audit.receipts.evidence", "CORRUPTED", f"{path}: evidence is invalid")
        elif evidence.get("run_id") != rec.get("attempt_id") or evidence.get("provider") != rec.get("provider"):
            add("effect_audit.receipts.evidence_binding", "CORRUPTED", f"{path}: evidence does not bind attempt/provider")
        if rec.get("outcome") not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
            add("effect_audit.receipts.outcome", "CORRUPTED", f"{path}: invalid outcome")
        trust = rec.get("source_authenticity")
        if not isinstance(trust, dict) or trust.get("level") not in ("PROVIDER_SIGNED", "AIOS_INVOKED_UNSIGNED"):
            add("effect_audit.receipts.source_authenticity", "UNSUPPORTED", f"{path}: source authenticity is legacy or unknown")
        elif trust.get("level") == "AIOS_INVOKED_UNSIGNED" and rec.get("attestation") is not None:
            add("effect_audit.receipts.source_authenticity", "CORRUPTED", f"{path}: unsigned receipt carries attestation")
        if name != rid + ".json":
            add("effect_audit.receipts.path_binding", "CORRUPTED", f"{path}: filename does not bind receipt_id")
        if rid in receipts:
            add("effect_audit.receipts.replay", "INCONSISTENT", f"duplicate receipt_id {rid}")
        receipts[rid] = rec
        effect = effects.get(eid)
        if effect is None:
            add("effect_audit.receipts.orphan", "INCONSISTENT", f"{path}: no effect {eid!r}")
        else:
            for field in ("attempt_id", "attempt", "contract_id", "provider"):
                if rec.get(field) != effect.get(field):
                    add("effect_audit.receipts.binding", "CORRUPTED", f"{path}: {field} differs from effect")
            if effect.get("receipt_id") != rid or effect.get("state") != rec.get("outcome"):
                add("effect_audit.receipts.not_of_record", "INCONSISTENT", f"{path}: effect does not name this terminal receipt")

    reconciliations = {}
    for name, path, rec in _files(os.path.join(aios_dir, "reconciliations"), add, "reconciliations"):
        _check_seal(rec, path, add)
        required = ("effect_id", "attempt", "attempt_id", "contract_id", "provider",
                    "verdict", "evidence", "actor", "outcome", "attestation", "source_authenticity")
        missing = [field for field in required if field not in rec]
        if rec.get("record_type") != "EFFECT_RECONCILIATION" or missing:
            add("effect_audit.reconciliations.schema", "CORRUPTED", f"{path}: invalid type or missing {missing}")
            continue
        trust = rec.get("source_authenticity")
        if rec.get("verdict") in ("APPLIED", "NOT_APPLIED") and (not isinstance(trust, dict) or trust.get("level") != "PROVIDER_SIGNED"):
            add("effect_audit.reconciliations.trust", "CORRUPTED", f"{path}: decisive verdict is not provider-signed")
        if rec.get("verdict") not in ("APPLIED", "NOT_APPLIED", "INCONCLUSIVE"):
            add("effect_audit.reconciliations.verdict", "CORRUPTED", f"{path}: invalid verdict")
        if isinstance(rec.get("attempt"), bool) or not isinstance(rec.get("attempt"), int) or rec.get("attempt", 0) < 1:
            add("effect_audit.reconciliations.attempt", "CORRUPTED", f"{path}: attempt must be a positive integer")
        evidence = rec.get("evidence")
        from .evidence import verify_evidence
        if not isinstance(evidence, dict) or not verify_evidence(evidence):
            add("effect_audit.reconciliations.evidence", "CORRUPTED", f"{path}: evidence is invalid")
        elif evidence.get("run_id") != rec.get("attempt_id") or evidence.get("provider") != rec.get("provider"):
            add("effect_audit.reconciliations.evidence_binding", "CORRUPTED", f"{path}: evidence does not bind attempt/provider")
        if rec.get("verdict") == "APPLIED" and rec.get("outcome") not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
            add("effect_audit.reconciliations.outcome", "CORRUPTED", f"{path}: APPLIED has invalid outcome")
        if rec.get("verdict") != "APPLIED" and rec.get("outcome") is not None:
            add("effect_audit.reconciliations.outcome", "CORRUPTED", f"{path}: non-APPLIED reconciliation carries outcome")
        key = (rec.get("effect_id"), rec.get("attempt"))
        if key in reconciliations:
            add("effect_audit.reconciliations.replay", "INCONSISTENT", f"{path}: duplicate reconciliation for {key}")
        reconciliations[key] = rec
        effect = effects.get(rec.get("effect_id"))
        if effect is None:
            add("effect_audit.reconciliations.orphan", "INCONSISTENT", f"{path}: effect is missing")
        else:
            if rec.get("attempt_id") != f"{rec.get('effect_id')}:attempt:{rec.get('attempt')}":
                add("effect_audit.reconciliations.binding", "CORRUPTED", f"{path}: attempt_id is not derived")
            for field in ("contract_id", "provider", "actor"):
                if rec.get(field) != effect.get(field):
                    add("effect_audit.reconciliations.binding", "CORRUPTED", f"{path}: {field} differs from effect")
            expected_name = f"{rec.get('effect_id')}-attempt-{rec.get('attempt')}.json"
            if name != expected_name:
                add("effect_audit.reconciliations.path_binding", "CORRUPTED", f"{path}: filename does not bind effect/attempt")
            if rec.get("verdict") not in ("APPLIED", "NOT_APPLIED", "INCONCLUSIVE"):
                add("effect_audit.reconciliations.verdict", "CORRUPTED", f"{path}: invalid verdict")
            if rec.get("verdict") == "APPLIED" and rec.get("outcome") not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
                add("effect_audit.reconciliations.outcome", "CORRUPTED", f"{path}: APPLIED has invalid outcome")

    evaluations = {}
    for name, path, rec in _files(os.path.join(aios_dir, "evaluations"), add, "evaluations"):
        _check_seal(rec, path, add)
        required = ("evaluation_id", "effect_id", "attempt_id", "receipt_id", "evaluator_version",
                    "rubric_version", "evidence_refs", "verdict", "timestamp", "result", "source_authenticity")
        missing = [field for field in required if field not in rec]
        if rec.get("record_type") != "EVALUATION" or missing:
            add("effect_audit.evaluations.schema", "CORRUPTED", f"{path}: invalid type or missing {missing}")
            continue
        eid = rec.get("evaluation_id")
        if not isinstance(eid, str) or name != eid + ".json":
            add("effect_audit.evaluations.path_binding", "CORRUPTED", f"{path}: filename does not bind evaluation_id")
        if eid in evaluations:
            add("effect_audit.evaluations.replay", "INCONSISTENT", f"{path}: duplicate evaluation_id {eid}")
        evaluations[eid] = rec
        identity = {"receipt_id": rec.get("receipt_id"), "evaluator_version": rec.get("evaluator_version"),
                    "rubric_version": rec.get("rubric_version")}
        expected_id = "EVAL-" + hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
        if eid != expected_id:
            add("effect_audit.evaluations.identity", "CORRUPTED", f"{path}: evaluation_id does not match its binding")
        receipt = receipts.get(rec.get("receipt_id"))
        if receipt is None:
            add("effect_audit.evaluations.orphan", "INCONSISTENT", f"{path}: referenced receipt is missing")
        else:
            for field in ("effect_id", "attempt_id"):
                if rec.get(field) != receipt.get(field):
                    add("effect_audit.evaluations.binding", "CORRUPTED", f"{path}: {field} differs from receipt")
            refs = rec.get("evidence_refs")
            evidence_id = (receipt.get("evidence") or {}).get("evidence_id") if isinstance(receipt.get("evidence"), dict) else None
            if not isinstance(refs, list) or not refs or any(ref != evidence_id for ref in refs):
                add("effect_audit.evaluations.evidence_binding", "CORRUPTED", f"{path}: evidence_refs do not bind receipt evidence")
            receipt_trust = receipt.get("source_authenticity")
            receipt_level = receipt_trust.get("level") if isinstance(receipt_trust, dict) else "LEGACY_UNVERIFIED"
            if rec.get("source_authenticity") != receipt_level:
                add("effect_audit.evaluations.trust_binding", "CORRUPTED", f"{path}: source_authenticity differs from receipt")

    claims = {}
    for name, path, rec in _files(os.path.join(aios_dir, "execution_claims"), add, "execution_claims"):
        _check_seal(rec, path, add)
        required = ("effect_id", "attempt", "attempt_id", "provider", "actor")
        missing = [field for field in required if field not in rec]
        if rec.get("record_type") != "EXECUTION_CLAIM" or rec.get("kind") != "execution_claim" or missing:
            add("effect_audit.claims.schema", "CORRUPTED", f"{path}: invalid type/kind or missing {missing}")
            continue
        key = (rec.get("effect_id"), rec.get("attempt"))
        if key in claims:
            add("effect_audit.claims.replay", "INCONSISTENT", f"{path}: duplicate claim for {key}")
        claims[key] = rec
        effect = effects.get(rec.get("effect_id"))
        if effect is None:
            add("effect_audit.claims.orphan", "INCONSISTENT", f"{path}: effect is missing")
        else:
            if rec.get("attempt_id") != f"{rec.get('effect_id')}:attempt:{rec.get('attempt')}":
                add("effect_audit.claims.binding", "CORRUPTED", f"{path}: attempt_id is not derived")
            for field in ("provider", "actor"):
                if rec.get(field) != effect.get(field):
                    add("effect_audit.claims.binding", "CORRUPTED", f"{path}: {field} differs from effect")
            expected_name = f"{rec.get('effect_id')}-attempt-{rec.get('attempt')}.json"
            if name != expected_name:
                add("effect_audit.claims.path_binding", "CORRUPTED", f"{path}: filename does not bind effect/attempt")

    # A terminal effect must have exactly its receipt of record; an active
    # dispatched attempt may legitimately have no receipt yet (crash window).
    for eid, effect in effects.items():
        state = effect.get("state")
        rid = effect.get("receipt_id")
        if state in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
            if not rid or rid not in receipts:
                add("effect_audit.effects.missing_receipt", "CORRUPTED", f"{eid}: terminal effect has no receipt")
        if state == "DISPATCHED":
            key = (eid, effect.get("attempt"))
            if key not in claims:
                add("effect_audit.effects.missing_claim", "INCONSISTENT", f"{eid}: DISPATCHED attempt has no execution claim")

    # External-effect events are a separate event family, not M1.5 mutation
    # events. Validate that each references a known effect and reject replays.
    seen_events = set()
    event_root = os.path.join(aios_dir, "events")
    for name, path, ev in _files(event_root, add, "effect_events"):
        if ev.get("kind") != "external_effect":
            continue
        eid = ev.get("effect_id")
        if not isinstance(eid, str) or eid not in effects:
            add("effect_audit.events.orphan", "INCONSISTENT", f"{path}: event references missing effect {eid!r}")
            continue
        effect = effects[eid]
        action = ev.get("action")
        allowed = {"create", "dispatch", "transition", "reconcile"}
        if action not in allowed:
            add("effect_audit.events.schema", "CORRUPTED", f"{path}: unknown external-effect action {action!r}")
        if not isinstance(ev.get("actor"), str) or not ev.get("actor", "").strip():
            add("effect_audit.events.schema", "CORRUPTED", f"{path}: missing actor")
        if action == "create":
            for field in ("contract_id", "permit_id", "effect_type", "state", "actor"):
                if ev.get(field) != effect.get(field):
                    add("effect_audit.events.binding", "CORRUPTED", f"{path}: create event {field} differs from effect")
            if ev.get("state") != "PLANNED":
                add("effect_audit.events.transition", "CORRUPTED", f"{path}: create event must establish PLANNED")
        elif action in ("dispatch", "transition", "reconcile"):
            attempt = ev.get("attempt")
            if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
                add("effect_audit.events.attempt", "CORRUPTED", f"{path}: {action} event has invalid attempt")
            if ev.get("attempt_id") is not None and ev.get("attempt_id") != f"{eid}:attempt:{attempt}":
                add("effect_audit.events.binding", "CORRUPTED", f"{path}: event attempt_id is not derived")
            if action == "dispatch":
                if ev.get("to_state") != "DISPATCHED" or not ev.get("provider"):
                    add("effect_audit.events.transition", "CORRUPTED", f"{path}: dispatch event lacks DISPATCHED/provider")
            if action == "transition" and ev.get("to_state") not in ("UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
                add("effect_audit.events.transition", "CORRUPTED", f"{path}: invalid transition target")
            if action == "reconcile" and ev.get("verdict") not in ("APPLIED", "NOT_APPLIED", "INCONCLUSIVE"):
                add("effect_audit.events.verdict", "CORRUPTED", f"{path}: invalid reconciliation verdict")
        key = (action, eid, ev.get("attempt"), ev.get("attempt_id"), ev.get("receipt_id"), ev.get("verdict"))
        if key in seen_events:
            add("effect_audit.events.replay", "INCONSISTENT", f"{path}: duplicate external-effect event identity")
        seen_events.add(key)
        if action == "create":
            seen_events.add(("create_seen", eid))
    for eid in effects:
        if ("create_seen", eid) not in seen_events:
            add("effect_audit.events.missing_create", "INCONSISTENT", f"{eid}: effect record has no create event")
