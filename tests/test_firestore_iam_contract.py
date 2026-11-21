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


def test_ingestion_role_is_create_read_only_and_evidence_only():
    source = TERRAFORM.read_text(encoding="utf-8")
    role = _role_block(source, "ci_ingestion")
    assert 'project     = var.ci_evidence_firestore_project_id' in role
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



def test_ci_ingestion_cannot_write_evolution_or_authority_projects():
    source = TERRAFORM.read_text(encoding="utf-8")
    assert 'resource "google_project_iam_member" "ci_ingestion_evidence"' in source
    assert 'resource "google_project_iam_member" "ci_ingestion_ledger"' not in source
    assert 'resource "google_project_iam_member" "ci_ingestion_authority"' not in source
    assert 'role    = google_project_iam_custom_role.capability_promotion.name\n  member  = "serviceAccount:${var.worker_runtime_service_account_email}"' not in source
    reader = _role_block(source, "ci_evidence_reader")
    assert '"datastore.entities.get"' in reader
    assert '"datastore.entities.create"' not in reader
    assert '"datastore.entities.update"' not in reader


def test_terraform_requires_five_distinct_firestore_projects():
    source = TERRAFORM.read_text(encoding="utf-8")
    assert 'check "firestore_projects_are_isolated"' in source
    for variable in (
        "var.project_id",
        "var.evolution_firestore_project_id",
        "var.authority_firestore_project_id",
        "var.ci_evidence_firestore_project_id",
        "var.activation_firestore_project_id",
    ):
        assert variable in source
    assert "var.ci_ingestion_service_account_email != var.capability_promotion_service_account_email" in source
    assert "var.worker_runtime_service_account_email != var.capability_promotion_service_account_email" in source
    assert "var.worker_runtime_service_account_email != var.ci_ingestion_service_account_email" in source


def test_worker_cannot_mutate_evolution_or_activation_pointer():
    source = TERRAFORM.read_text(encoding="utf-8")
    worker_evolution = re.search(r'resource "google_project_iam_custom_role" "worker_evolution_reader" \{(.*?)\n\}', source, re.DOTALL)
    assert worker_evolution
    assert '"datastore.entities.get"' in worker_evolution.group(1)
    assert '"datastore.entities.update"' not in worker_evolution.group(1)
    activation_reader = _role_block(source, "activation_pointer_reader")
    assert '"datastore.entities.get"' in activation_reader
    assert '"datastore.entities.create"' not in activation_reader
    assert '"datastore.entities.update"' not in activation_reader
    activation_writer = _role_block(source, "activation_pointer_writer")
    assert 'project     = var.activation_firestore_project_id' in activation_writer
    assert '"datastore.entities.update"' in activation_writer
