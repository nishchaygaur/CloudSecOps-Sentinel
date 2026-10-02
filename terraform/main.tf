terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.30.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.30.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# -----------------------------------------------------------------------------
# 1. Enable Required GCP APIs
# -----------------------------------------------------------------------------
locals {
  base_services = [
    "logging.googleapis.com",
    "pubsub.googleapis.com",
    "bigquery.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "storage.googleapis.com",
    "cloudtrace.googleapis.com"
  ]
  cloud_run_services = var.enable_cloud_run ? [
    "run.googleapis.com",
    "aiplatform.googleapis.com",
    "eventarc.googleapis.com"
  ] : []
  services = concat(local.base_services, local.cloud_run_services)
}

resource "google_project_service" "enabled_apis" {
  for_each           = toset(local.services)
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

# -----------------------------------------------------------------------------
# 2. Service Accounts & Least Privilege IAM
# -----------------------------------------------------------------------------
module "iam" {
  source     = "./modules/iam"
  project_id = var.project_id
  depends_on = [google_project_service.enabled_apis]
}

# -----------------------------------------------------------------------------
# 3. BigQuery SIEM Data Lake
# -----------------------------------------------------------------------------
module "bigquery_siem" {
  source     = "./modules/bigquery_siem"
  project_id = var.project_id
  region     = var.region
  depends_on = [google_project_service.enabled_apis]
}

# -----------------------------------------------------------------------------
# 4. Cloud Pub/Sub Telemetry Pipelines
# -----------------------------------------------------------------------------
module "pubsub" {
  source                     = "./modules/pubsub"
  project_id                 = var.project_id
  detector_service_account   = module.iam.detector_sa_email
  remediator_service_account = module.iam.remediator_sa_email
  depends_on                 = [google_project_service.enabled_apis]
}

# -----------------------------------------------------------------------------
# 5. Cloud Logging Sinks (Capturing Admin Activity & System Events)
# -----------------------------------------------------------------------------
module "audit_sinks" {
  source       = "./modules/audit_sinks"
  project_id   = var.project_id
  pubsub_topic = module.pubsub.telemetry_topic_id
  depends_on   = [module.pubsub]
}

# -----------------------------------------------------------------------------
# 6. Cloud Run Serverless Services (Detector, Remediator, AI Analyst)
# -----------------------------------------------------------------------------
module "cloud_run" {
  count                 = var.enable_cloud_run ? 1 : 0
  source                = "./modules/cloud_run"
  project_id            = var.project_id
  region                = var.region
  detector_sa_email     = module.iam.detector_sa_email
  remediator_sa_email   = module.iam.remediator_sa_email
  ai_analyst_sa_email   = module.iam.ai_analyst_sa_email
  telemetry_topic_name  = module.pubsub.telemetry_topic_name
  alerts_topic_name     = module.pubsub.alerts_topic_name
  bq_dataset_id         = module.bigquery_siem.dataset_id
  depends_on            = [module.bigquery_siem, module.pubsub, module.iam]
}
