terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0, < 8.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_project" "current" {
  project_id = var.project_id
}

# Own the complete run.invoker binding for this service. This removes
# allUsers and any other unlisted invokers; review the plan before applying.
resource "google_cloud_run_v2_service_iam_binding" "private_invokers" {
  project  = var.project_id
  location = var.region
  name     = var.worker_service_name
  role     = "roles/run.invoker"
  members = [
    "serviceAccount:${var.cloud_tasks_invoker_email}",
    "serviceAccount:${var.scheduler_invoker_email}",
  ]
}

# The worker project is a dedicated effect/attempt/receipt data plane.
# It needs direct reads, outbox queries, creates and state transitions, but
# it never needs to delete durable evidence.
resource "google_project_iam_custom_role" "worker_effect_runtime" {
  project     = var.project_id
  role_id     = "aiosWorkerEffectRuntime"
  title       = "AIOS Worker Effect Runtime"
  description = "Read/query and create/update durable worker effects; no delete."
  permissions = [
    "datastore.databases.get",
    "datastore.entities.create",
    "datastore.entities.get",
    "datastore.entities.list",
    "datastore.entities.update",
  ]
  stage = "GA"
}

resource "google_project_iam_member" "worker_firestore" {
  project = var.project_id
  role    = google_project_iam_custom_role.worker_effect_runtime.name
  member  = "serviceAccount:${var.worker_runtime_service_account_email}"
}

resource "google_cloud_tasks_queue_iam_member" "worker_enqueue" {
  project  = var.project_id
  location = var.cloud_tasks_location
  name     = var.cloud_tasks_queue_name
  role     = "roles/cloudtasks.enqueuer"
  member   = "serviceAccount:${var.worker_runtime_service_account_email}"
}

# Google-managed service agents need permission to mint the OIDC tokens used
# by Cloud Tasks and Cloud Scheduler. These grants are scoped to the two
# dedicated invoker service accounts, not the project.
resource "google_service_account_iam_member" "worker_can_act_as_cloud_tasks_invoker" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.cloud_tasks_invoker_email}"
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${var.worker_runtime_service_account_email}"
}

data "google_secret_manager_secret" "authority_attestation" {
  project   = var.project_id
  secret_id = var.authority_attestation_secret_id
}

resource "google_secret_manager_secret_iam_member" "worker_authority_attestation" {
  project   = var.project_id
  secret_id = data.google_secret_manager_secret.authority_attestation.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.worker_runtime_service_account_email}"
}

resource "google_service_account_iam_member" "cloud_tasks_token_creator" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.cloud_tasks_invoker_email}"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudtasks.iam.gserviceaccount.com"
}

resource "google_service_account_iam_member" "scheduler_token_creator" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.scheduler_invoker_email}"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
}

resource "google_cloud_scheduler_job" "outbox_reconciler" {
  project     = var.project_id
  region      = var.region
  name        = var.scheduler_job_name
  description = "Wake the AIOS durable Firestore dispatch outbox."
  schedule    = var.scheduler_schedule
  time_zone   = var.scheduler_time_zone

  http_target {
    http_method = "POST"
    uri         = "${trimsuffix(var.worker_service_uri, "/")}/outbox/reconcile"
    body        = base64encode("{}")
    headers = {
      "Content-Type" = "application/json"
    }
    oidc_token {
      service_account_email = var.scheduler_invoker_email
      audience              = trimsuffix(var.worker_service_uri, "/")
    }
  }

  depends_on = [
    google_cloud_run_v2_service_iam_binding.private_invokers,
    google_service_account_iam_member.scheduler_token_creator,
  ]
}

variable "project_id" {
  description = "Existing GCP project ID. This module does not create a project."
  type        = string
}

variable "region" {
  description = "Region of the existing Cloud Run service and Scheduler job."
  type        = string
}

variable "worker_service_name" {
  description = "Name of the existing private Cloud Run worker service."
  type        = string
}

variable "worker_service_uri" {
  description = "HTTPS base URI of the existing Cloud Run worker service."
  type        = string
  validation {
    condition     = startswith(var.worker_service_uri, "https://")
    error_message = "worker_service_uri must be an HTTPS URL."
  }
}

variable "worker_runtime_service_account_email" {
  description = "Service account attached to Cloud Run; reads Firestore and enqueues Cloud Tasks."
  type        = string
}

variable "cloud_tasks_invoker_email" {
  description = "Dedicated service account used by Cloud Tasks OIDC to invoke /dispatch."
  type        = string
}

variable "scheduler_invoker_email" {
  description = "Dedicated service account used by Cloud Scheduler OIDC to invoke /outbox/reconcile."
  type        = string
}

variable "cloud_tasks_location" {
  description = "Location of the existing Cloud Tasks queue."
  type        = string
}

variable "cloud_tasks_queue_name" {
  description = "Name of the existing Cloud Tasks queue; the queue is not created here."
  type        = string
}

variable "scheduler_job_name" {
  description = "Name for the Cloud Scheduler job."
  type        = string
}

variable "scheduler_schedule" {
  description = "Cron schedule supplied by the deployment owner; no cadence is assumed."
  type        = string
}

variable "scheduler_time_zone" {
  description = "IANA time zone for the supplied scheduler schedule."
  type        = string
}

variable "authority_attestation_secret_id" {
  description = "Name of the existing Secret Manager secret containing the authority attestation HMAC key."
  type        = string
}

# Evolution ledger and authority artifacts live in different GCP projects.
# Firestore IAM is project-scoped here; these projects must contain only the
# corresponding data plane. No database, project, or service account is created.
variable "evolution_firestore_project_id" {
  description = "Dedicated existing project containing only the M10/M11 evolution ledger."
  type        = string
}

variable "authority_firestore_project_id" {
  description = "Dedicated existing project containing signed authority artifacts only."
  type        = string
}

variable "activation_firestore_project_id" {
  description = "Dedicated existing project containing only the active capability pointer projection."
  type        = string
}

variable "ci_evidence_firestore_project_id" {
  description = "Dedicated existing project containing only GitHub CI evidence and ingestion events."
  type        = string
}

variable "ci_ingestion_service_account_email" {
  description = "Existing GitHub OIDC identity used only by the CI evidence ingestion workflow."
  type        = string
}

variable "capability_promotion_service_account_email" {
  description = "Existing GitHub OIDC identity used only by the capability promotion workflow."
  type        = string
}

variable "github_actions_ingestion_wif_principal" {
  description = "WIF principalSet restricted to the CI evidence ingestion workflow identity."
  type        = string
}

variable "github_actions_promotion_wif_principal" {
  description = "WIF principalSet restricted to the capability promotion workflow identity."
  type        = string
}

check "firestore_projects_are_isolated" {
  assert {
    condition = (
      var.evolution_firestore_project_id != var.authority_firestore_project_id &&
      var.evolution_firestore_project_id != var.ci_evidence_firestore_project_id &&
      var.authority_firestore_project_id != var.ci_evidence_firestore_project_id &&
      var.activation_firestore_project_id != var.evolution_firestore_project_id &&
      var.activation_firestore_project_id != var.authority_firestore_project_id &&
      var.activation_firestore_project_id != var.ci_evidence_firestore_project_id &&
      var.activation_firestore_project_id != var.project_id &&
      var.evolution_firestore_project_id != var.project_id &&
      var.authority_firestore_project_id != var.project_id &&
      var.ci_evidence_firestore_project_id != var.project_id
    )
    error_message = "Worker, evolution, authority, CI evidence, and activation Firestore projects must be five distinct existing projects."
  }
}

check "automation_identities_are_isolated" {
  assert {
    condition = (
      var.ci_ingestion_service_account_email != var.capability_promotion_service_account_email &&
      var.github_actions_ingestion_wif_principal != var.github_actions_promotion_wif_principal
    )
    error_message = "CI ingestion and capability promotion must use distinct service accounts and distinct WIF principals."
  }
}

# The ingestion role can read and create documents only. It cannot update,
# delete, list, or write any authority artifact.
resource "google_project_iam_custom_role" "ci_ingestion" {
  project     = var.ci_evidence_firestore_project_id
  role_id     = "aiosCiEvidenceIngestion"
  title       = "AIOS CI Evidence Ingestion"
  description = "Read existing evidence IDs and create immutable CI evidence documents; no update/delete/list."
  permissions = [
    "datastore.databases.get",
    "datastore.entities.create",
    "datastore.entities.get",
  ]
  stage = "GA"
}

# Promotion needs direct document reads, create-only ledger records, and
# updates to governed evolution projections. Active pointers use a separate project.
resource "google_project_iam_custom_role" "capability_promotion" {
  project     = var.evolution_firestore_project_id
  role_id     = "aiosCapabilityPromotion"
  title       = "AIOS Capability Promotion"
  description = "Read/create evolution records and update governed projections; no delete/list."
  permissions = [
    "datastore.databases.get",
    "datastore.entities.create",
    "datastore.entities.get",
    "datastore.entities.update",
  ]
  stage = "GA"
}

resource "google_project_iam_member" "ci_ingestion_evidence" {
  project = var.ci_evidence_firestore_project_id
  role    = google_project_iam_custom_role.ci_ingestion.name
  member  = "serviceAccount:${var.ci_ingestion_service_account_email}"
}

resource "google_project_iam_custom_role" "ci_evidence_reader" {
  project     = var.ci_evidence_firestore_project_id
  role_id     = "aiosCiEvidenceReader"
  title       = "AIOS CI Evidence Reader"
  description = "Read individual immutable CI evidence records; no writes or listing."
  permissions = [
    "datastore.entities.get",
  ]
  stage = "GA"
}

resource "google_project_iam_member" "capability_promotion_evidence_readonly" {
  project = var.ci_evidence_firestore_project_id
  role    = google_project_iam_custom_role.ci_evidence_reader.name
  member  = "serviceAccount:${var.capability_promotion_service_account_email}"
}

resource "google_project_iam_member" "capability_promotion_ledger" {
  project = var.evolution_firestore_project_id
  role    = google_project_iam_custom_role.capability_promotion.name
  member  = "serviceAccount:${var.capability_promotion_service_account_email}"
}

# Only the isolated promotion identity may mutate active pointers. Worker is read-only.
resource "google_project_iam_custom_role" "activation_pointer_writer" {
  project     = var.activation_firestore_project_id
  role_id     = "aiosActivationPointerWriter"
  title       = "AIOS Activation Pointer Writer"
  description = "Read/create/update active capability pointers; no delete/list."
  permissions = ["datastore.entities.get", "datastore.entities.create", "datastore.entities.update"]
  stage       = "GA"
}

resource "google_project_iam_member" "promotion_activation_writer" {
  project = var.activation_firestore_project_id
  role    = google_project_iam_custom_role.activation_pointer_writer.name
  member  = "serviceAccount:${var.capability_promotion_service_account_email}"
}

resource "google_project_iam_custom_role" "activation_pointer_reader" {
  project     = var.activation_firestore_project_id
  role_id     = "aiosActivationPointerReader"
  title       = "AIOS Activation Pointer Reader"
  description = "Read active capability pointers only."
  permissions = ["datastore.entities.get"]
  stage       = "GA"
}

resource "google_project_iam_member" "worker_activation_readonly" {
  project = var.activation_firestore_project_id
  role    = google_project_iam_custom_role.activation_pointer_reader.name
  member  = "serviceAccount:${var.worker_runtime_service_account_email}"
}

# Promotion verifies signed artifacts but cannot create, update or delete them.
resource "google_project_iam_custom_role" "authority_artifact_reader" {
  project     = var.authority_firestore_project_id
  role_id     = "aiosAuthorityArtifactReader"
  title       = "AIOS Authority Artifact Reader"
  description = "Read individual signed authority documents only; no writes or collection listing."
  permissions = [
    "datastore.entities.get",
  ]
  stage = "GA"
}

resource "google_project_iam_member" "capability_promotion_authority_readonly" {
  project = var.authority_firestore_project_id
  role    = google_project_iam_custom_role.authority_artifact_reader.name
  member  = "serviceAccount:${var.capability_promotion_service_account_email}"
}

# Runtime needs to resolve signed authority artifacts but cannot mutate or
# enumerate the authority store.
resource "google_project_iam_custom_role" "worker_evolution_reader" {
  project     = var.evolution_firestore_project_id
  role_id     = "aiosEvolutionReader"
  title       = "AIOS Evolution Reader"
  description = "Read evolution ledger documents only; no mutation or collection listing."
  permissions = ["datastore.entities.get"]
  stage       = "GA"
}

resource "google_project_iam_member" "worker_evolution_ledger" {
  project = var.evolution_firestore_project_id
  role    = google_project_iam_custom_role.worker_evolution_reader.name
  member  = "serviceAccount:${var.worker_runtime_service_account_email}"
}

resource "google_project_iam_member" "worker_authority_readonly" {
  project = var.authority_firestore_project_id
  role    = google_project_iam_custom_role.authority_artifact_reader.name
  member  = "serviceAccount:${var.worker_runtime_service_account_email}"
}

resource "google_service_account_iam_member" "github_actions_ingestion_wif" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.ci_ingestion_service_account_email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = var.github_actions_ingestion_wif_principal
}

resource "google_service_account_iam_member" "github_actions_promotion_wif" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.capability_promotion_service_account_email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = var.github_actions_promotion_wif_principal
}
