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

resource "google_project_iam_member" "worker_firestore" {
  project = var.project_id
  role    = "roles/datastore.user"
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
