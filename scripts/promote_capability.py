"""Execute the Firestore M11 promotion gate using signed authority artifacts."""
from __future__ import annotations

import argparse
import json
import os


def client_and_store():
    import google.auth
    from google.cloud import firestore
    from core.firestore_authority import FirestoreAuthorityStore
    from core.firestore_evolution_store import FirestoreEvolutionStore

    evolution_project_id = os.environ.get("AIOS_EVOLUTION_FIRESTORE_PROJECT_ID", "").strip()
    authority_project_id = os.environ.get("AIOS_AUTHORITY_FIRESTORE_PROJECT_ID", "").strip()
    evidence_project_id = os.environ.get("AIOS_CI_EVIDENCE_FIRESTORE_PROJECT_ID", "").strip()
    if not evolution_project_id or not authority_project_id or not evidence_project_id:
        raise RuntimeError("evolution, authority, and CI evidence Firestore project IDs are required")
    if len({evolution_project_id, authority_project_id, evidence_project_id}) != 3:
        raise RuntimeError("evolution, authority, and CI evidence Firestore projects must be distinct")
    trust_anchor = FirestoreAuthorityStore.trust_anchor_from_env()
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/datastore"])
    evolution_client = firestore.Client(project=evolution_project_id, credentials=credentials)
    authority_client = firestore.Client(project=authority_project_id, credentials=credentials)
    evidence_client = firestore.Client(project=evidence_project_id, credentials=credentials)
    if (evolution_client.project != evolution_project_id or authority_client.project != authority_project_id
            or evidence_client.project != evidence_project_id):
        raise RuntimeError("Firestore client project mismatch")
    authority = FirestoreAuthorityStore(authority_client, project_id=authority_project_id)
    workflow_pin = os.environ.get("AIOS_FIRESTORE_WORKFLOW_SHA256", "").strip().lower()
    if len(workflow_pin) != 64:
        raise RuntimeError("AIOS_FIRESTORE_WORKFLOW_SHA256 reviewed pin is required")
    return FirestoreEvolutionStore(evolution_client, project_id=evolution_project_id, authority_store=authority,
                                   trust_anchor=trust_anchor,
                                   expected_workflow_sha256=workflow_pin)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    bootstrap = sub.add_parser("bootstrap")
    bootstrap.add_argument("--capability-digest", required=True)
    bootstrap.add_argument("--decision-digest", required=True)
    promote = sub.add_parser("promote")
    promote.add_argument("--candidate-id", required=True)
    promote.add_argument("--evaluation-id", required=True)
    promote.add_argument("--decision-digest", required=True)
    promote.add_argument("--capability-digest", required=True)
    promote.add_argument("--repository", required=True)
    args = parser.parse_args()
    store = client_and_store()
    if args.command == "bootstrap":
        result = store.bootstrap_active_capability(
            capability_digest=args.capability_digest,
            bootstrap_decision_digest=args.decision_digest,
        )
    else:
        result = store.promote_candidate(
            candidate_id=args.candidate_id, evaluation_id=args.evaluation_id,
            decision_digest=args.decision_digest, capability_digest=args.capability_digest,
            repository=args.repository,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
