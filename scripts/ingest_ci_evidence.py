"""Ingest a completed, successful GitHub Actions Firestore gate into Firestore.

This runs from a separate workflow_run workflow after the source workflow has
completed. It never executes downloaded artifacts; it hashes the ZIP bytes and
stores GitHub API provenance plus the immutable artifact digest.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

EXPECTED_WORKFLOW = ".github/workflows/firestore-emulator.yml"


def verify_artifact_digest(artifact: dict, zip_bytes: bytes) -> str:
    """Require GitHub's artifact digest and verify the downloaded ZIP bytes."""
    if not isinstance(artifact, dict):
        raise RuntimeError("GitHub artifact metadata is malformed")
    expected = artifact.get("digest")
    if not isinstance(expected, str) or not expected.startswith("sha256:"):
        raise RuntimeError("GitHub artifact metadata has no SHA-256 digest")
    expected_hex = expected.removeprefix("sha256:").lower()
    if len(expected_hex) != 64 or any(ch not in "0123456789abcdef" for ch in expected_hex):
        raise RuntimeError("GitHub artifact SHA-256 digest is malformed")
    actual = hashlib.sha256(zip_bytes).hexdigest()
    if actual != expected_hex:
        raise RuntimeError("downloaded artifact bytes do not match GitHub artifact digest")
    return actual


def api(url: str, token: str) -> tuple[dict, bytes]:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AIOS-CI-Evidence-Ingestor",
    })
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read()
            content_type = response.headers.get("Content-Type", "")
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"GitHub API request failed: {url}") from exc
    if "zip" in content_type or "octet-stream" in content_type:
        return {}, raw
    try:
        return json.loads(raw.decode("utf-8")), raw
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GitHub API returned non-JSON metadata") from exc


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    expected_repository = os.environ.get("AIOS_EXPECTED_REPOSITORY", "yanhul/AIOS")
    run_id = os.environ.get("AIOS_SOURCE_RUN_ID")
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not token or repository != expected_repository or not run_id or not run_id.isdigit():
        raise RuntimeError("GitHub token, expected repository and source run ID are required")
    base = f"{api_url}/repos/{repository}/actions"
    run, _ = api(f"{base}/runs/{run_id}", token)
    if run.get("repository", {}).get("full_name") != expected_repository:
        raise RuntimeError("source workflow repository mismatch")
    if run.get("path", "").split("@", 1)[0] != EXPECTED_WORKFLOW:
        raise RuntimeError("source workflow path is not the pinned Firestore Emulator Gate")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise RuntimeError("source workflow run is not completed successfully")
    if run.get("event") not in {"pull_request", "push", "workflow_dispatch"}:
        raise RuntimeError("source workflow event is not allowed")
    if run.get("head_repository", {}).get("full_name") != expected_repository:
        raise RuntimeError("fork-origin workflow evidence is not accepted")
    head_sha = run.get("head_sha", "")
    if len(head_sha) not in (40, 64) or any(ch not in "0123456789abcdef" for ch in head_sha):
        raise RuntimeError("source workflow head SHA is malformed")
    expected_workflow_sha = os.environ.get("AIOS_FIRESTORE_WORKFLOW_SHA256", "").strip().lower()
    if len(expected_workflow_sha) != 64 or any(ch not in "0123456789abcdef" for ch in expected_workflow_sha):
        raise RuntimeError("AIOS_FIRESTORE_WORKFLOW_SHA256 must pin the reviewed workflow source")
    workflow_source, _ = api(
        f"{api_url}/repos/{repository}/contents/{EXPECTED_WORKFLOW}?ref={head_sha}", token
    )
    if workflow_source.get("encoding") != "base64" or not isinstance(workflow_source.get("content"), str):
        raise RuntimeError("could not retrieve source workflow bytes for pin verification")
    try:
        workflow_bytes = base64.b64decode("".join(workflow_source["content"].split()), validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("source workflow content is not valid base64") from exc
    workflow_sha = hashlib.sha256(workflow_bytes).hexdigest()
    if workflow_sha != expected_workflow_sha:
        raise RuntimeError("source workflow file digest differs from reviewed pinned workflow")

    jobs_payload, _ = api(f"{base}/runs/{run_id}/jobs?per_page=100", token)
    jobs = jobs_payload.get("jobs", [])
    required = [j for j in jobs if j.get("name") == "firestore-emulator"]
    if len(required) != 1 or required[0].get("status") != "completed" or required[0].get("conclusion") != "success":
        raise RuntimeError("the Firestore Emulator job did not complete successfully exactly once")
    if any(j.get("status") != "completed" or j.get("conclusion") != "success" for j in jobs):
        raise RuntimeError("source workflow contains a failed, cancelled, skipped or incomplete job")

    artifacts_payload, _ = api(f"{base}/runs/{run_id}/artifacts?per_page=100", token)
    artifact_name = f"firestore-emulator-{run_id}"
    artifacts = [a for a in artifacts_payload.get("artifacts", []) if a.get("name") == artifact_name]
    if len(artifacts) != 1 or artifacts[0].get("expired") is not False:
        raise RuntimeError("expected non-expired emulator log artifact is missing or ambiguous")
    artifact = artifacts[0]
    _, zip_bytes = api(f"{base}/artifacts/{artifact['id']}/zip", token)
    artifact_digest = verify_artifact_digest(artifact, zip_bytes)

    from google.cloud import firestore
    import google.auth
    from core.firestore_authority import FirestoreAuthorityStore
    from core.firestore_evolution_store import FirestoreEvolutionStore

    evolution_project_id = os.environ.get("AIOS_EVOLUTION_FIRESTORE_PROJECT_ID", "").strip()
    authority_project_id = os.environ.get("AIOS_AUTHORITY_FIRESTORE_PROJECT_ID", "").strip()
    if not evolution_project_id or not authority_project_id:
        raise RuntimeError("both evolution and authority Firestore project IDs are required")
    if evolution_project_id == authority_project_id:
        raise RuntimeError("evolution and authority Firestore projects must be distinct")
    trust_anchor = FirestoreAuthorityStore.trust_anchor_from_env()
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/datastore"])
    evolution_client = firestore.Client(project=evolution_project_id, credentials=credentials)
    authority_client = firestore.Client(project=authority_project_id, credentials=credentials)
    if evolution_client.project != evolution_project_id or authority_client.project != authority_project_id:
        raise RuntimeError("Firestore client project mismatch")
    authority = FirestoreAuthorityStore(authority_client, project_id=authority_project_id)
    workflow_pin = os.environ.get("AIOS_FIRESTORE_WORKFLOW_SHA256", "").strip().lower()
    if len(workflow_pin) != 64:
        raise RuntimeError("AIOS_FIRESTORE_WORKFLOW_SHA256 reviewed pin is required")
    store = FirestoreEvolutionStore(evolution_client, project_id=evolution_project_id, authority_store=authority,
                                    trust_anchor=trust_anchor,
                                    expected_workflow_sha256=workflow_pin)
    record = {
        "repository": expected_repository,
        "workflow_id": run["workflow_id"],
        "workflow_path": EXPECTED_WORKFLOW,
        "workflow_sha256": workflow_sha,
        "workflow_name": run.get("name", "Firestore Emulator Gate"),
        "run_id": int(run_id),
        "run_attempt": int(run.get("run_attempt", 1)),
        "run_url": run.get("html_url", ""),
        "head_branch": run.get("head_branch", ""),
        "head_sha": head_sha,
        "event": run["event"],
        "conclusion": run["conclusion"],
        "jobs": [{"id": j["id"], "name": j["name"], "conclusion": j["conclusion"]} for j in required],
        "artifact_digests": [{"name": artifact_name, "id": artifact["id"],
                              "size_in_bytes": artifact.get("size_in_bytes"), "sha256": artifact_digest}],
    }
    result = store.record_ci_evidence(record, actor="github-actions:ci-evidence-ingestor")
    summary = {**result, "head_sha": head_sha, "run_id": int(run_id), "run_url": run.get("html_url", "")}
    rendered = json.dumps(summary, sort_keys=True)
    print(rendered)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write("## AIOS CI evidence stored\n\n")
            handle.write(f"- Evidence reference: `{result['evidence_ref']}`\n")
            handle.write(f"- Source commit: `{head_sha}`\n")
            handle.write(f"- Source run: [{run_id}]({run.get('html_url', '')})\n")
            handle.write(f"- Artifact SHA-256: `{artifact_digest}`\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"CI_EVIDENCE_INGESTION_BLOCKED: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
