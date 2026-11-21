"""Firestore-backed M10/M11 evidence, candidate, evaluation and activation ledger.

The store is not an issuer. Promotion requires independently signed authority
artifacts in FirestoreAuthorityStore and a successful GitHub Actions evidence
record. Immutable records/events are appended transactionally; the active
capability document is a CAS-controlled projection of signed decisions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from collections.abc import Callable, Mapping
from typing import Any

from .firestore_authority import FirestoreAuthorityStore


class EvolutionStoreError(RuntimeError):
    """Evolution ledger rejected an invalid or unconfirmed transition."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(value: Mapping[str, Any]) -> str:
    return sha256(_canonical(dict(value)).encode("utf-8")).hexdigest()


_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvolutionStoreError(f"{name} must be a non-empty string")
    return value.strip()


def _verify_record(record: Mapping[str, Any], prefix: str) -> None:
    identity = record.get("identity")
    record_id = record.get("record_id")
    logical = {k: v for k, v in record.items() if k not in {"created_at", "record_id", "identity"}}
    if not isinstance(identity, str) or not _SHA256.fullmatch(identity) or identity != _digest(logical) or record_id != prefix + identity:
        raise EvolutionStoreError("Firestore evolution record content identity mismatch")


def _data(snapshot: Any) -> dict[str, Any] | None:
    if not getattr(snapshot, "exists", False):
        return None
    value = snapshot.to_dict()
    if not isinstance(value, dict):
        raise EvolutionStoreError("Firestore evolution document is not an object")
    return value


class FirestoreEvolutionStore:
    """Transactional persistence and signed promotion gate for M10/M11."""

    def __init__(
        self, client: Any, *, project_id: str, authority_store: FirestoreAuthorityStore,
        trust_anchor: Mapping[str, Mapping[str, Any]], evidence_client: Any | None = None,
        activation_client: Any | None = None,
        transaction_runner: Callable[[Any, Callable[[Any], Any]], Any] | None = None,
        evidence_verifier: Callable[[list[str], str], bool] | None = None,
        expected_workflow_sha256: str | None = None,
    ) -> None:
        if not isinstance(project_id, str) or not project_id.strip():
            raise EvolutionStoreError("explicit Firestore project ID required")
        if getattr(client, "project", None) != project_id:
            raise EvolutionStoreError("Firestore client project mismatch")
        if not isinstance(trust_anchor, Mapping) or not trust_anchor:
            raise EvolutionStoreError("pinned authority trust anchor required")
        self.client, self.project_id = client, project_id
        self.evidence_client = evidence_client if evidence_client is not None else client
        evidence_project = getattr(self.evidence_client, "project", None)
        if not isinstance(evidence_project, str) or not evidence_project.strip():
            raise EvolutionStoreError("explicit CI evidence Firestore client project required")
        self.evidence_project_id = evidence_project
        self.activation_client = activation_client if activation_client is not None else client
        activation_project = getattr(self.activation_client, "project", None)
        if not isinstance(activation_project, str) or not activation_project.strip():
            raise EvolutionStoreError("explicit activation Firestore client project required")
        self.activation_project_id = activation_project
        self.authority_store, self.trust_anchor = authority_store, trust_anchor
        self.evidence_verifier = evidence_verifier
        if expected_workflow_sha256 is not None and not _SHA256.fullmatch(expected_workflow_sha256):
            raise EvolutionStoreError("expected workflow SHA-256 pin is malformed")
        self.expected_workflow_sha256 = expected_workflow_sha256
        if transaction_runner is None:
            try:
                from google.cloud.firestore_v1.transaction import transactional
            except ImportError as exc:
                raise EvolutionStoreError("google-cloud-firestore is required") from exc

            def run(client_obj: Any, callback: Callable[[Any], Any]) -> Any:
                tx = client_obj.transaction(max_attempts=5)

                @transactional
                def invoke(transaction: Any) -> Any:
                    return callback(transaction)

                return invoke(tx)
            transaction_runner = run
        self._run = transaction_runner

    def _ref(self, collection: str, document_id: str) -> Any:
        if not document_id or "/" in document_id:
            raise EvolutionStoreError("invalid Firestore document ID")
        if collection in {"aios_ci_evidence", "aios_ci_evidence_events"}:
            client = self.evidence_client
        elif collection == "aios_active_capabilities":
            client = self.activation_client
        else:
            client = self.client
        return client.collection(collection).document(document_id)

    def _commit(self, label: str, callback: Callable[[Any], Any], *, client: Any | None = None) -> Any:
        try:
            return self._run(client if client is not None else self.client, callback)
        except EvolutionStoreError:
            raise
        except Exception as exc:
            raise EvolutionStoreError(f"{label} was not confirmed; state remains unchanged/unknown") from exc

    def _append(self, *, collection: str, prefix: str, record: Mapping[str, Any], actor: str, action: str,
                precondition: Callable[[Any], None] | None = None,
                record_id_override: str | None = None,
                event_collection: str = "aios_evolution_events",
                client: Any | None = None) -> dict[str, Any]:
        actor = _required(actor, "actor")
        body = dict(record)
        identity = _digest(body)
        record_id = record_id_override or prefix + identity
        stored = {**body, "record_id": record_id, "identity": identity,
                  "created_at": datetime.now(timezone.utc).isoformat(timespec="microseconds")}
        event = {"event_type": action, "actor": actor, "record_type": body.get("record_type"),
                 "record_id": record_id, "record_identity": identity,
                 "capability_id": body.get("capability_id"), "candidate_id": body.get("candidate_id"),
                 "outcome": body.get("outcome"), "verdict": body.get("verdict")}
        event_id = _digest(event)
        record_ref = self._ref(collection, record_id)
        event_ref = self._ref(event_collection, event_id)

        def body_tx(tx: Any) -> dict[str, Any]:
            old = _data(record_ref.get(transaction=tx))
            old_event = _data(event_ref.get(transaction=tx))
            if old is not None:
                logical = {k: v for k, v in old.items() if k != "created_at"}
                expected = {**body, "record_id": record_id, "identity": identity}
                if logical != expected or old_event != event:
                    raise EvolutionStoreError("immutable evolution record/event conflict")
                return {"record_id": record_id, "identity": identity, "replayed": True}
            if old_event is not None:
                raise EvolutionStoreError("orphan evolution audit event")
            if precondition is not None:
                precondition(tx)
            tx.create(record_ref, stored)
            tx.create(event_ref, event)
            return {"record_id": record_id, "identity": identity, "replayed": False}
        return self._commit(f"{action} transaction", body_tx, client=client)

    def record_experience(self, record: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
        body = dict(record)
        if body.get("record_type") != "EXPERIENCE":
            raise EvolutionStoreError("record_type must be EXPERIENCE")
        for key in ("capability_id", "capability_version", "task_id", "contributor", "run_id", "source_commit", "artifact_digest"):
            _required(body.get(key), key)
        if not _COMMIT.fullmatch(body["source_commit"]) or not _SHA256.fullmatch(body["artifact_digest"]):
            raise EvolutionStoreError("experience source commit or artifact digest is malformed")
        refs = body.get("evidence_refs")
        if not isinstance(refs, list) or not refs or any(not isinstance(x, str) or not x for x in refs) or len(set(refs)) != len(refs):
            raise EvolutionStoreError("experience requires unique non-empty evidence_refs")
        if body.get("outcome") == "PASS":
            required = ("effect_id", "attempt_id", "receipt_id", "verifier", "evaluation_id", "verification_status")
            if any(not isinstance(body.get(k), str) or not body[k].strip() for k in required):
                raise EvolutionStoreError("PASS experience lacks exact execution/evaluation lineage")
            if body.get("verification_status") not in {"VERIFIED_DIGITAL", "VERIFIED_PHYSICAL"}:
                raise EvolutionStoreError("PASS experience lacks recognized verification status")
            if body.get("verifier") == body.get("contributor"):
                raise EvolutionStoreError("experience contributor cannot verify their own PASS")
            if self.evidence_verifier is not None and self.evidence_verifier(refs, body.get("source_commit", "")) is not True:
                raise EvolutionStoreError("additional PASS evidence verification was not successful")
            precondition = lambda tx: self._verify_pass_experience(body, transaction=tx)
        elif body.get("outcome") not in {"BLOCKED", "INCONCLUSIVE"}:
            raise EvolutionStoreError("experience outcome must be PASS, BLOCKED or INCONCLUSIVE")
        else:
            precondition = None
        return self._append(collection="aios_experiences", prefix="XP-", record=body,
                             actor=actor, action="experience.recorded", precondition=precondition)

    def _verify_pass_experience(self, body: Mapping[str, Any], *, transaction: Any | None = None) -> None:
        """Bind PASS experience to the exact terminal Firestore receipt and M11 evaluation."""
        effect_id = _required(body.get("effect_id"), "effect_id")
        attempt_id = _required(body.get("attempt_id"), "attempt_id")
        receipt_id = _required(body.get("receipt_id"), "receipt_id")
        evaluation_id = _required(body.get("evaluation_id"), "evaluation_id")
        effect = _data(self._ref("effects", effect_id).get(transaction=transaction))
        attempt_key = sha256(attempt_id.encode("utf-8")).hexdigest()
        attempt_ref = self.client.collection("effects").document(effect_id).collection("attempts").document(attempt_key)
        attempt = _data(attempt_ref.get(transaction=transaction))
        receipt = _data(self._ref("provider_receipts", receipt_id).get(transaction=transaction))
        evaluation = _data(self._ref("aios_capability_evaluations", evaluation_id).get(transaction=transaction))
        latest_evaluation = _data(self._ref("aios_capability_latest_evaluations", evaluation.get("candidate_id") if evaluation else "missing").get(transaction=transaction))
        if effect is None or attempt is None or receipt is None or evaluation is None:
            raise EvolutionStoreError("PASS experience effect/attempt/receipt/evaluation evidence is incomplete")
        _verify_record(evaluation, "CE-")
        candidate_id = evaluation.get("candidate_id")
        candidate = _data(self._ref("aios_capability_candidates", candidate_id).get(transaction=transaction))
        if candidate is None:
            raise EvolutionStoreError("PASS experience candidate provenance is missing")
        _verify_record(candidate, "CV-")
        if (effect.get("effect_id") != effect_id or effect.get("attempt_id") != attempt_id
                or effect.get("state") != "OBSERVED_SUCCESS" or effect.get("provider_receipt_id") != receipt_id
                or attempt.get("effect_id") != effect_id or attempt.get("attempt_id") != attempt_id
                or attempt.get("state") != "OBSERVED_SUCCESS" or attempt.get("provider_receipt_id") != receipt_id):
            raise EvolutionStoreError("PASS experience does not bind the exact OBSERVED_SUCCESS attempt")
        if (receipt.get("record_type") != "AIOS_TERMINAL_PROVIDER_RECEIPT"
                or receipt.get("receipt_id") != receipt_id or receipt.get("effect_id") != effect_id
                or receipt.get("attempt_id") != attempt_id or receipt.get("outcome") != "OBSERVED_SUCCESS"
                or not effect.get("contract_id") or receipt.get("contract_id") != effect.get("contract_id")
                or not effect.get("permit_id") or receipt.get("permit_id") != effect.get("permit_id")
                or not effect.get("provider") or receipt.get("provider") != effect.get("provider")
                or not receipt.get("provider_operation_id")
                or effect.get("provider_operation_id") != receipt.get("provider_operation_id")
                or attempt.get("provider") != effect.get("provider")
                or not isinstance(receipt.get("authentication"), Mapping)
                or not receipt.get("authentication")):
            raise EvolutionStoreError("PASS experience receipt is not a verified terminal receipt for this attempt")
        lineage_binding = effect.get("execution_lineage") or {}
        lineage = lineage_binding.get("lineage") or {}
        if not isinstance(lineage.get("lineage_digest"), str) or not lineage["lineage_digest"]:
            raise EvolutionStoreError("PASS experience effect has no verified execution lineage digest")
        if receipt.get("lineage_digest") != lineage.get("lineage_digest"):
            raise EvolutionStoreError("PASS experience receipt execution lineage mismatch")
        if (evaluation.get("verdict") != "PASS" or evaluation.get("evaluator") != body.get("verifier")
                or latest_evaluation is None or latest_evaluation.get("evaluation_id") != evaluation_id
                or latest_evaluation.get("verdict") != "PASS"
                or candidate.get("capability_id") != body.get("capability_id")
                or candidate.get("candidate_version") != body.get("capability_version")
                or candidate.get("source_commit") != body.get("source_commit")):
            raise EvolutionStoreError("PASS experience does not bind an independent PASS evaluation for this capability commit")
        m11_refs = sorted(set(candidate.get("evidence_refs", []) + evaluation.get("evidence_refs", [])))
        ci_refs = [ref for ref in m11_refs if isinstance(ref, str) and ref.startswith("ci://CI-")]
        if not ci_refs:
            raise EvolutionStoreError("PASS experience requires successful CI evidence linked to candidate and evaluation")
        ci_records = self._read_ci_refs(ci_refs, body["source_commit"], repository=None, transaction=transaction)
        repositories = {record.get("repository") for record in ci_records}
        if len(repositories) != 1:
            raise EvolutionStoreError("PASS experience CI evidence spans multiple repositories")
        non_ci_refs = [ref for ref in m11_refs if ref not in ci_refs]
        if non_ci_refs and (self.evidence_verifier is None or self.evidence_verifier(non_ci_refs, body["source_commit"]) is not True):
            raise EvolutionStoreError("PASS experience non-CI evidence was not independently verified")
        required_refs = {
            f"effect://{effect_id}", f"attempt://{effect_id}/{attempt_id}",
            f"receipt://{receipt_id}", f"evaluation://{evaluation_id}",
        }
        if not required_refs.issubset(set(body.get("evidence_refs", []))) or not set(m11_refs).issubset(set(body.get("evidence_refs", []))):
            raise EvolutionStoreError("PASS experience evidence_refs omit exact execution or candidate/evaluation references")

    def propose_candidate(self, record: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
        body = dict(record)
        if body.get("record_type") != "CAPABILITY_CANDIDATE":
            raise EvolutionStoreError("record_type must be CAPABILITY_CANDIDATE")
        for key in ("capability_id", "base_version", "candidate_version", "proposer", "source_commit", "patch_digest", "run_id"):
            _required(body.get(key), key)
        base_match = _SEMVER.fullmatch(body["base_version"])
        candidate_match = _SEMVER.fullmatch(body["candidate_version"])
        if not base_match or not candidate_match or tuple(map(int, candidate_match.groups())) <= tuple(map(int, base_match.groups())):
            raise EvolutionStoreError("candidate version must be a greater MAJOR.MINOR.PATCH")
        if not _COMMIT.fullmatch(body["source_commit"]) or not _SHA256.fullmatch(body["patch_digest"]):
            raise EvolutionStoreError("candidate source commit or patch digest is malformed")
        _required(body.get("change_summary"), "change_summary")
        if not isinstance(body.get("evidence_refs"), list) or not body["evidence_refs"] or any(not isinstance(x, str) or not x for x in body["evidence_refs"]) or len(set(body["evidence_refs"])) != len(body["evidence_refs"]):
            raise EvolutionStoreError("candidate evidence_refs required")
        return self._append(collection="aios_capability_candidates", prefix="CV-", record=body,
                             actor=actor, action="capability.candidate_proposed")

    def evaluate_candidate(self, record: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
        body = dict(record)
        candidate_id = _required(body.get("candidate_id"), "candidate_id")
        candidate = _data(self._ref("aios_capability_candidates", candidate_id).get())
        if candidate is None:
            raise EvolutionStoreError("unknown capability candidate")
        _verify_record(candidate, "CV-")
        if body.get("evaluator") == candidate.get("proposer"):
            raise EvolutionStoreError("candidate proposer cannot evaluate their own candidate")
        if body.get("verdict") not in {"PASS", "FAIL", "INCONCLUSIVE"}:
            raise EvolutionStoreError("invalid evaluation verdict")
        for key in ("evaluator", "evaluator_version", "test_suite_digest", "comparison_digest", "run_id"):
            _required(body.get(key), key)
        if not _SHA256.fullmatch(body["test_suite_digest"]) or not _SHA256.fullmatch(body["comparison_digest"]):
            raise EvolutionStoreError("evaluation test/comparison digest is malformed")
        if not isinstance(body.get("evidence_refs"), list) or not body["evidence_refs"] or any(not isinstance(x, str) or not x for x in body["evidence_refs"]) or len(set(body["evidence_refs"])) != len(body["evidence_refs"]):
            raise EvolutionStoreError("evaluation evidence_refs required")
        body["record_type"] = "CAPABILITY_EVALUATION"
        body["capability_id"] = candidate["capability_id"]
        # Append the evaluation and move the latest-evaluation pointer atomically.
        actor = _required(actor, "actor")
        identity = _digest(body)
        evaluation_id = "CE-" + identity
        stored = {**body, "record_id": evaluation_id, "identity": identity,
                  "created_at": datetime.now(timezone.utc).isoformat(timespec="microseconds")}
        event = {"event_type": "capability.candidate_evaluated", "actor": actor,
                 "record_type": "CAPABILITY_EVALUATION", "record_id": evaluation_id,
                 "record_identity": identity, "candidate_id": candidate_id,
                 "capability_id": candidate["capability_id"], "verdict": body["verdict"]}
        event_id = _digest(event)
        eval_ref = self._ref("aios_capability_evaluations", evaluation_id)
        event_ref = self._ref("aios_evolution_events", event_id)
        latest_ref = self._ref("aios_capability_latest_evaluations", candidate_id)
        candidate_ref = self._ref("aios_capability_candidates", candidate_id)

        def body_tx(tx: Any) -> dict[str, Any]:
            current_candidate = _data(candidate_ref.get(transaction=tx))
            existing_evaluation = _data(eval_ref.get(transaction=tx))
            old_event = _data(event_ref.get(transaction=tx))
            latest = _data(latest_ref.get(transaction=tx))
            if current_candidate != candidate:
                raise EvolutionStoreError("candidate changed during evaluation; reload before append")
            if existing_evaluation is not None:
                logical = {k: v for k, v in existing_evaluation.items() if k != "created_at"}
                if logical != {**body, "record_id": evaluation_id, "identity": identity} or old_event != event:
                    raise EvolutionStoreError("immutable evaluation replay conflict")
                return {"evaluation_id": evaluation_id, "verdict": body["verdict"], "replayed": True}
            if old_event is not None:
                raise EvolutionStoreError("orphan evaluation event")
            sequence = int((latest or {}).get("sequence", 0)) + 1
            tx.create(eval_ref, stored)
            tx.create(event_ref, event)
            tx.set(latest_ref, {"candidate_id": candidate_id, "evaluation_id": evaluation_id,
                                "verdict": body["verdict"], "sequence": sequence})
            return {"evaluation_id": evaluation_id, "verdict": body["verdict"], "sequence": sequence, "replayed": False}
        return self._commit("candidate evaluation transaction", body_tx)

    def record_ci_evidence(self, record: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
        body = dict(record)
        required = ("repository", "workflow_id", "workflow_path", "workflow_sha256", "run_id", "run_attempt",
                    "head_sha", "event", "conclusion", "jobs", "artifact_digests")
        for key in required:
            if key not in body:
                raise EvolutionStoreError(f"CI evidence missing {key}")
        if body["workflow_path"] != ".github/workflows/firestore-emulator.yml":
            raise EvolutionStoreError("CI evidence must originate from the pinned Firestore Emulator workflow")
        if (not isinstance(body["workflow_sha256"], str) or not _SHA256.fullmatch(body["workflow_sha256"])
                or self.expected_workflow_sha256 is None
                or body["workflow_sha256"] != self.expected_workflow_sha256):
            raise EvolutionStoreError("CI evidence must match the configured reviewed workflow source digest")
        if (not isinstance(body["workflow_id"], int) or isinstance(body["workflow_id"], bool) or body["workflow_id"] < 1
                or not isinstance(body["run_id"], int) or isinstance(body["run_id"], bool) or body["run_id"] < 1
                or not isinstance(body["run_attempt"], int) or isinstance(body["run_attempt"], bool) or body["run_attempt"] < 1
                or not isinstance(body["head_sha"], str) or not _COMMIT.fullmatch(body["head_sha"])):
            raise EvolutionStoreError("CI workflow/run identity or head SHA is malformed")
        if body["conclusion"] != "success" or body["event"] not in {"pull_request", "push", "workflow_dispatch"}:
            raise EvolutionStoreError("CI run is not an accepted successful event")
        if not isinstance(body["jobs"], list) or not body["jobs"] or any(j.get("conclusion") != "success" for j in body["jobs"]):
            raise EvolutionStoreError("all CI jobs must have successful conclusions")
        if not any(j.get("name") == "firestore-emulator" and j.get("conclusion") == "success" for j in body["jobs"]):
            raise EvolutionStoreError("Firestore Emulator Gate job did not pass")
        if not isinstance(body["artifact_digests"], list) or not body["artifact_digests"]:
            raise EvolutionStoreError("successful emulator artifact digest is required")
        if not any(isinstance(a, Mapping) and isinstance(a.get("name"), str)
                   and a["name"].startswith("firestore-emulator-")
                   and isinstance(a.get("sha256"), str) and _SHA256.fullmatch(a["sha256"])
                   for a in body["artifact_digests"]):
            raise EvolutionStoreError("Firestore Emulator artifact must be SHA-256 bound")
        body["record_type"] = "GITHUB_CI_EVIDENCE"
        stable_run_id = f"CI-{body['workflow_id']}-{body['run_id']}-{body['run_attempt']}"
        result = self._append(collection="aios_ci_evidence", prefix="CI-", record=body,
                              actor=actor, action="ci.evidence_ingested",
                              record_id_override=stable_run_id,
                              event_collection="aios_ci_evidence_events",
                              client=self.evidence_client)
        return {**result, "evidence_ref": "ci://" + result["record_id"]}

    def _read_ci_refs(self, refs: list[str], source_commit: str, repository: str | None,
                      transaction: Any | None = None) -> list[dict[str, Any]]:
        verified = []
        for value in refs:
            ref = _required(value, "evidence_ref")
            if not ref.startswith("ci://CI-"):
                continue
            record_id = ref[len("ci://"):]
            record = _data(self._ref("aios_ci_evidence", record_id).get(transaction=transaction))
            if record is None:
                raise EvolutionStoreError("referenced CI evidence record is missing")
            logical = {k: v for k, v in record.items() if k not in {"created_at", "record_id", "identity"}}
            if _digest(logical) != record.get("identity") or record.get("record_id") != record_id:
                raise EvolutionStoreError("CI evidence content identity mismatch")
            if ((repository is not None and record.get("repository") != repository)
                    or record.get("head_sha") != source_commit):
                raise EvolutionStoreError("CI evidence repository/commit does not bind candidate")
            artifacts = record.get("artifact_digests", [])
            if (record.get("conclusion") != "success"
                    or record.get("workflow_path") != ".github/workflows/firestore-emulator.yml"
                    or not isinstance(record.get("workflow_sha256"), str)
                    or not _SHA256.fullmatch(record["workflow_sha256"])
                    or self.expected_workflow_sha256 is None
                    or record["workflow_sha256"] != self.expected_workflow_sha256
                    or not isinstance(record.get("workflow_id"), int)
                    or not isinstance(record.get("run_id"), int)
                    or not isinstance(record.get("run_attempt"), int)
                    or not isinstance(record.get("head_sha"), str) or not _COMMIT.fullmatch(record["head_sha"])
                    or any(j.get("conclusion") != "success" for j in record.get("jobs", []))
                    or not any(j.get("name") == "firestore-emulator" and j.get("conclusion") == "success" for j in record.get("jobs", []))
                    or not any(isinstance(a, Mapping) and isinstance(a.get("name"), str)
                               and a["name"].startswith("firestore-emulator-")
                               and isinstance(a.get("sha256"), str) and _SHA256.fullmatch(a["sha256"])
                               for a in artifacts)):
                raise EvolutionStoreError("CI evidence is not from the successful pinned Firestore Emulator workflow")
            verified.append(record)
        if not verified:
            raise EvolutionStoreError("promotion requires at least one immutable GitHub CI evidence record")
        return verified

    def promote_candidate(
        self, *, candidate_id: str, evaluation_id: str, decision_digest: str,
        capability_digest: str, repository: str,
    ) -> dict[str, Any]:
        """Atomically activate a signed capability after CI/evaluation/authority gates."""
        candidate_id = _required(candidate_id, "candidate_id")
        evaluation_id = _required(evaluation_id, "evaluation_id")
        decision = self.authority_store.get_verified(
            decision_digest, trust_anchor=self.trust_anchor,
            expected_type="CAPABILITY_PROMOTION_DECISION",
        )
        capability = self.authority_store.get_verified(
            capability_digest, trust_anchor=self.trust_anchor, expected_type="CAPABILITY"
        )
        candidate = _data(self._ref("aios_capability_candidates", candidate_id).get())
        evaluation = _data(self._ref("aios_capability_evaluations", evaluation_id).get())
        if candidate is None or evaluation is None:
            raise EvolutionStoreError("candidate or evaluation missing")
        _verify_record(candidate, "CV-")
        _verify_record(evaluation, "CE-")
        if evaluation.get("candidate_id") != candidate_id or evaluation.get("verdict") != "PASS":
            raise EvolutionStoreError("evaluation is not a PASS for this exact candidate")
        latest = _data(self._ref("aios_capability_latest_evaluations", candidate_id).get())
        if latest is None or latest.get("evaluation_id") != evaluation_id or latest.get("verdict") != "PASS":
            raise EvolutionStoreError("evaluation is not the latest candidate evaluation")
        if len({candidate.get("proposer"), evaluation.get("evaluator"), decision.get("approver")}) != 3:
            raise EvolutionStoreError("proposer, evaluator and approver must be distinct")
        refs = sorted(set(candidate.get("evidence_refs", []) + evaluation.get("evidence_refs", [])))
        ci_records = self._read_ci_refs(refs, candidate["source_commit"], repository)
        non_ci_refs = [ref for ref in refs if not ref.startswith("ci://CI-")]
        if non_ci_refs and (self.evidence_verifier is None or self.evidence_verifier(non_ci_refs, candidate["source_commit"]) is not True):
            raise EvolutionStoreError("non-CI candidate evidence was not independently verified")
        active_ref = self._ref("aios_active_capabilities", candidate["capability_id"])
        active_before = _data(active_ref.get())
        if active_before is None:
            raise EvolutionStoreError("active capability base pointer is missing; promotion blocked")
        if (active_before.get("decision_digest") == decision_digest
                and active_before.get("capability_digest") == capability_digest):
            # Idempotent replay of the exact decision already activated.
            prior_decision_digest = active_before.get("previous_decision_digest")
            next_revision = active_before.get("revision")
        else:
            if active_before.get("version") != candidate["base_version"]:
                raise EvolutionStoreError("active capability base version mismatch; promotion blocked")
            prior_decision_digest = active_before.get("decision_digest") or active_before.get("bootstrap_decision_digest")
            next_revision = active_before.get("revision")
            if not isinstance(next_revision, int) or isinstance(next_revision, bool) or next_revision < 0:
                raise EvolutionStoreError("active capability revision is malformed")
            next_revision += 1
        expected_decision = {
            "decision": "PROMOTED", "candidate_id": candidate_id,
            "evaluation_id": evaluation_id, "capability_id": candidate["capability_id"],
            "from_version": candidate["base_version"], "to_version": candidate["candidate_version"],
            "approver": decision.get("approver"), "evidence_refs": refs,
            "capability_digest": capability_digest, "revision": next_revision,
            "previous_decision_digest": prior_decision_digest,
        }
        if any(decision.get(k) != v for k, v in expected_decision.items()):
            raise EvolutionStoreError("signed promotion decision does not bind exact candidate/evaluation/evidence/capability")
        expected_capability = {
            "capability_id": candidate["capability_id"], "version": candidate["candidate_version"],
            "status": "ACTIVE", "source_commit": candidate["source_commit"],
            "patch_digest": candidate["patch_digest"], "candidate_id": candidate_id,
            "evaluation_id": evaluation_id,
        }
        if any(capability.get(k) != v for k, v in expected_capability.items()):
            raise EvolutionStoreError("signed ACTIVE capability does not bind exact evaluated candidate")
        decision_ref = self._ref("aios_capability_decisions", "CD-" + decision_digest)
        event = {"event_type": "capability.version_promoted", "decision_digest": decision_digest,
                 "capability_digest": capability_digest, "candidate_id": candidate_id,
                 "evaluation_id": evaluation_id, "capability_id": candidate["capability_id"],
                 "from_version": candidate["base_version"], "to_version": candidate["candidate_version"],
                 "ci_evidence_ids": [r["record_id"] for r in ci_records]}
        event_id = _digest(event)
        event_ref = self._ref("aios_evolution_events", event_id)

        def body_tx(tx: Any) -> dict[str, Any]:
            current_candidate = _data(self._ref("aios_capability_candidates", candidate_id).get(transaction=tx))
            current_eval = _data(self._ref("aios_capability_evaluations", evaluation_id).get(transaction=tx))
            current_latest = _data(self._ref("aios_capability_latest_evaluations", candidate_id).get(transaction=tx))
            old_decision = _data(decision_ref.get(transaction=tx))
            old_event = _data(event_ref.get(transaction=tx))
            operation_ref = self._ref("aios_activation_operations", "PROMOTE-" + decision_digest)
            old_operation = _data(operation_ref.get(transaction=tx))
            if current_candidate != candidate or current_eval != evaluation or current_latest != latest:
                raise EvolutionStoreError("candidate/evaluation changed during promotion; retry from fresh evidence")
            if old_decision is not None:
                if (old_decision.get("decision_digest") != decision_digest
                        or old_decision.get("capability_digest") != capability_digest
                        or old_event != event or old_operation is None):
                    raise EvolutionStoreError("promotion prepare replay conflicts with durable ledger")
                if old_operation.get("state") not in {"PREPARED", "ACTIVATED"}:
                    raise EvolutionStoreError("promotion operation has invalid state")
                return {"status": "PREPARED", "replayed": True, "decision_digest": decision_digest,
                        "capability_digest": capability_digest, "version": candidate["candidate_version"]}
            if old_event is not None or old_operation is not None:
                raise EvolutionStoreError("orphan promotion event/activation operation")
            tx.create(decision_ref, {**event, "record_type": "CAPABILITY_DECISION",
                                     "decision": "PROMOTED", "approver": decision["approver"],
                                     "decision_digest": decision_digest, "capability_digest": capability_digest})
            tx.create(event_ref, event)
            tx.create(operation_ref, {"operation_id": "PROMOTE-" + decision_digest, "state": "PREPARED",
                                      "decision_digest": decision_digest, "capability_digest": capability_digest,
                                      "capability_id": candidate["capability_id"],
                                      "from_version": candidate["base_version"],
                                      "version": candidate["candidate_version"],
                                      "revision": next_revision,
                                      "previous_decision_digest": prior_decision_digest})
            return {"status": "PREPARED", "replayed": False, "decision_digest": decision_digest,
                    "capability_digest": capability_digest, "version": candidate["candidate_version"],
                    "revision": next_revision}
        prepared = self._commit("capability activation prepare transaction", body_tx)
        operation_id = "PROMOTE-" + decision_digest
        operation_ref = self._ref("aios_activation_operations", operation_id)
        def activate_tx(tx: Any) -> bool:
            pointer = _data(active_ref.get(transaction=tx))
            expected_pointer = {"capability_id": candidate["capability_id"],
                                "version": candidate["candidate_version"],
                                "capability_digest": capability_digest,
                                "decision_digest": decision_digest,
                                "previous_decision_digest": prior_decision_digest,
                                "revision": next_revision}
            if pointer == expected_pointer:
                return True
            if (pointer is None or pointer.get("version") != candidate["base_version"]
                    or pointer.get("revision") != next_revision - 1
                    or (pointer.get("decision_digest") or pointer.get("bootstrap_decision_digest")) != prior_decision_digest):
                raise EvolutionStoreError("activation CAS conflict; operation remains PREPARED")
            tx.set(active_ref, expected_pointer)
            return False
        replayed = self._commit("activation pointer CAS", activate_tx, client=self.activation_client)
        def finalize_tx(tx: Any) -> None:
            op = _data(operation_ref.get(transaction=tx))
            if op is None or op.get("decision_digest") != decision_digest or op.get("capability_digest") != capability_digest:
                raise EvolutionStoreError("activation operation missing or conflicting")
            if op.get("state") == "ACTIVATED":
                return
            if op.get("state") != "PREPARED":
                raise EvolutionStoreError("activation operation cannot be finalized")
            tx.set(operation_ref, {**op, "state": "ACTIVATED"})
        self._commit("activation finalize transaction", finalize_tx)
        return {**prepared, "status": "ACTIVE", "replayed": bool(prepared.get("replayed") or replayed),
                "activation_state": "ACTIVATED"}

    def bootstrap_active_capability(self, *, capability_digest: str, bootstrap_decision_digest: str) -> dict[str, Any]:
        """Create the first active pointer from two independently signed artifacts."""
        decision = self.authority_store.get_verified(
            bootstrap_decision_digest, trust_anchor=self.trust_anchor,
            expected_type="CAPABILITY_BOOTSTRAP_DECISION",
        )
        capability = self.authority_store.get_verified(
            capability_digest, trust_anchor=self.trust_anchor, expected_type="CAPABILITY"
        )
        expected = {
            "decision": "BOOTSTRAP_ACTIVE", "capability_id": capability.get("capability_id"),
            "version": capability.get("version"), "capability_digest": capability_digest,
            "revision": 0, "previous_decision_digest": None,
        }
        if capability.get("status") != "ACTIVE" or any(decision.get(k) != v for k, v in expected.items()):
            raise EvolutionStoreError("signed bootstrap decision does not bind exact ACTIVE capability")
        capability_id = _required(capability.get("capability_id"), "capability_id")
        pointer_ref = self._ref("aios_active_capabilities", capability_id)
        decision_ref = self._ref("aios_capability_decisions", "CD-BOOTSTRAP-" + bootstrap_decision_digest)
        event = {"event_type": "capability.registry_bootstrapped", "capability_id": capability_id,
                 "version": capability["version"], "capability_digest": capability_digest,
                 "bootstrap_decision_digest": bootstrap_decision_digest}
        event_id = _digest(event)
        event_ref = self._ref("aios_evolution_events", event_id)

        def body_tx(tx: Any) -> dict[str, Any]:
            old_decision = _data(decision_ref.get(transaction=tx))
            old_event = _data(event_ref.get(transaction=tx))
            operation_ref = self._ref("aios_activation_operations", "BOOTSTRAP-" + bootstrap_decision_digest)
            old_operation = _data(operation_ref.get(transaction=tx))
            if old_decision is not None:
                if old_event != event or old_operation is None or old_operation.get("state") not in {"PREPARED", "ACTIVATED"}:
                    raise EvolutionStoreError("bootstrap prepare replay conflicts")
                return {"status": "PREPARED", "replayed": True, "version": capability["version"]}
            if old_event is not None or old_operation is not None:
                raise EvolutionStoreError("orphan bootstrap event/operation")
            tx.create(decision_ref, {**event, "record_type": "CAPABILITY_DECISION", "decision": "BOOTSTRAP_ACTIVE"})
            tx.create(event_ref, event)
            tx.create(operation_ref, {"operation_id": "BOOTSTRAP-" + bootstrap_decision_digest,
                                      "state": "PREPARED", "decision_digest": bootstrap_decision_digest,
                                      "capability_digest": capability_digest, "capability_id": capability_id,
                                      "version": capability["version"], "revision": 0,
                                      "previous_decision_digest": None})
            return {"status": "PREPARED", "replayed": False, "version": capability["version"], "revision": 0}
        prepared = self._commit("active capability bootstrap prepare", body_tx)
        operation_ref = self._ref("aios_activation_operations", "BOOTSTRAP-" + bootstrap_decision_digest)
        def activate_tx(tx: Any) -> bool:
            current = _data(pointer_ref.get(transaction=tx))
            expected_pointer = {"capability_id": capability_id, "version": capability["version"],
                                "capability_digest": capability_digest,
                                "bootstrap_decision_digest": bootstrap_decision_digest,
                                "previous_decision_digest": None, "revision": 0}
            if current == expected_pointer:
                return True
            if current is not None:
                raise EvolutionStoreError("active capability pointer already exists; bootstrap is create-only")
            tx.create(pointer_ref, expected_pointer)
            return False
        replayed = self._commit("bootstrap activation pointer create", activate_tx, client=self.activation_client)
        def finalize_tx(tx: Any) -> None:
            op = _data(operation_ref.get(transaction=tx))
            if op is None or op.get("decision_digest") != bootstrap_decision_digest or op.get("capability_digest") != capability_digest:
                raise EvolutionStoreError("bootstrap operation missing or conflicting")
            if op.get("state") == "ACTIVATED":
                return
            if op.get("state") != "PREPARED":
                raise EvolutionStoreError("bootstrap operation cannot be finalized")
            tx.set(operation_ref, {**op, "state": "ACTIVATED"})
        self._commit("bootstrap activation finalize", finalize_tx)
        return {**prepared, "status": "ACTIVE", "replayed": bool(prepared.get("replayed") or replayed),
                "activation_state": "ACTIVATED"}

    def get_active_capability(self, capability_id: str) -> dict[str, Any]:
        pointer = _data(self._ref("aios_active_capabilities", _required(capability_id, "capability_id")).get())
        if pointer is None:
            raise EvolutionStoreError("no active capability pointer; DENY")
        record = self.authority_store.get_verified(
            pointer.get("capability_digest", ""), trust_anchor=self.trust_anchor,
            expected_type="CAPABILITY",
        )
        if record.get("capability_id") != capability_id or record.get("version") != pointer.get("version") or record.get("status") != "ACTIVE":
            raise EvolutionStoreError("active pointer does not bind signed ACTIVE capability; DENY")
        if pointer.get("bootstrap_decision_digest"):
            decision = self.authority_store.get_verified(
                pointer["bootstrap_decision_digest"], trust_anchor=self.trust_anchor,
                expected_type="CAPABILITY_BOOTSTRAP_DECISION",
            )
            if (decision.get("capability_digest") != pointer["capability_digest"]
                    or decision.get("revision") != pointer.get("revision")
                    or decision.get("previous_decision_digest") != pointer.get("previous_decision_digest")):
                raise EvolutionStoreError("active bootstrap pointer has invalid signed decision; DENY")
        else:
            decision = self.authority_store.get_verified(
                pointer.get("decision_digest", ""), trust_anchor=self.trust_anchor,
                expected_type="CAPABILITY_PROMOTION_DECISION",
            )
            if (decision.get("capability_digest") != pointer["capability_digest"]
                    or decision.get("to_version") != pointer["version"]
                    or decision.get("capability_id") != capability_id
                    or decision.get("revision") != pointer.get("revision")
                    or decision.get("previous_decision_digest") != pointer.get("previous_decision_digest")):
                raise EvolutionStoreError("active pointer has invalid signed promotion decision; DENY")
        return {"pointer": pointer, "capability": record}


__all__ = ["EvolutionStoreError", "FirestoreEvolutionStore"]
