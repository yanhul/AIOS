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

    project_id = os.environ.get("AIOS_FIRESTORE_PROJECT_ID", "").strip()
    if not project_id:
        raise RuntimeError("AIOS_FIRESTORE_PROJECT_ID is required")
    trust_anchor = FirestoreAuthorityStore.trust_anchor_from_env()
    credentials, adc_project = google.auth.default(scopes=["https://www.googleapis.com/auth/datastore"])
    if adc_project and adc_project != project_id:
        raise RuntimeError("ADC project mismatch")
    client = firestore.Client(project=project_id, credentials=credentials)
    authority = FirestoreAuthorityStore(client, project_id=project_id)
    workflow_pin = os.environ.get("AIOS_FIRESTORE_WORKFLOW_SHA256", "").strip().lower()
    if len(workflow_pin) != 64:
        raise RuntimeError("AIOS_FIRESTORE_WORKFLOW_SHA256 reviewed pin is required")
    return FirestoreEvolutionStore(client, project_id=project_id, authority_store=authority,
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
