from pathlib import Path
import re


TERRAFORM = Path("infra/cloudrun/worker_access.tf")


def _role_block(source: str, resource_name: str) -> str:
    match = re.search(
        rf'resource "google_project_iam_custom_role" "{re.escape(resource_name)}" \{{(.*?)\n\}}',
        source,
        re.DOTALL,
    )
    assert match, f"missing custom IAM role: {resource_name}"
    return match.group(1)


def test_firestore_automation_does_not_use_broad_datastore_user_role():
    source = TERRAFORM.read_text(encoding="utf-8")
    assert '"roles/datastore.user"' not in source


def test_ingestion_role_is_create_read_only():
    role = _role_block(TERRAFORM.read_text(encoding="utf-8"), "ci_ingestion")
    assert '"datastore.entities.create"' in role
    assert '"datastore.entities.get"' in role
    assert '"datastore.entities.update"' not in role
    assert '"datastore.entities.delete"' not in role
    assert '"datastore.entities.list"' not in role


def test_promotion_and_worker_roles_cannot_delete_durable_records():
    source = TERRAFORM.read_text(encoding="utf-8")
    for name in ("capability_promotion", "worker_effect_runtime"):
        role = _role_block(source, name)
        assert '"datastore.entities.delete"' not in role
        assert '"datastore.entities.create"' in role
        assert '"datastore.entities.get"' in role
        assert '"datastore.entities.update"' in role


def test_authority_reader_is_read_only_and_does_not_enumerate_documents():
    role = _role_block(TERRAFORM.read_text(encoding="utf-8"), "authority_artifact_reader")
    assert '"datastore.entities.get"' in role
    assert '"datastore.entities.create"' not in role
    assert '"datastore.entities.update"' not in role
    assert '"datastore.entities.delete"' not in role
    assert '"datastore.entities.list"' not in role
