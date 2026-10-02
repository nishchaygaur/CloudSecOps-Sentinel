# -----------------------------------------------------------------------------
# 1. Detection Engine Service Account
# -----------------------------------------------------------------------------
resource "google_service_account" "detector" {
  project      = var.project_id
  account_id   = "sa-sentinel-detector"
  display_name = "CloudSecOps Sentinel Detection Engine"
  description  = "Evaluates telemetry against MITRE ATT&CK rules and streams to BigQuery"
}

resource "google_project_iam_member" "detector_roles" {
  for_each = toset([
    "roles/bigquery.dataEditor",
    "roles/bigquery.jobUser",
    "roles/pubsub.publisher",
    "roles/pubsub.subscriber"
  ])
  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.detector.email}"
}

# -----------------------------------------------------------------------------
# 2. Automated SOAR Remediator Service Account
# -----------------------------------------------------------------------------
resource "google_service_account" "remediator" {
  project      = var.project_id
  account_id   = "sa-sentinel-remediator"
  display_name = "CloudSecOps Sentinel Auto-Remediator (SOAR)"
  description  = "Performs automated rollback and containment on compromised GCP resources"
}

resource "google_project_iam_member" "remediator_roles" {
  for_each = toset([
    "roles/iam.serviceAccountKeyAdmin",
    "roles/storage.admin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/compute.securityAdmin",
    "roles/pubsub.subscriber"
  ])
  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.remediator.email}"
}

# -----------------------------------------------------------------------------
# 3. AI SecOps Incident Analyst Service Account
# -----------------------------------------------------------------------------
resource "google_service_account" "ai_analyst" {
  project      = var.project_id
  account_id   = "sa-sentinel-ai-analyst"
  display_name = "CloudSecOps Sentinel Gemini AI Analyst"
  description  = "Queries BigQuery for incident timeline and calls Vertex AI Gemini for triage"
}

resource "google_project_iam_member" "ai_analyst_roles" {
  for_each = toset([
    "roles/bigquery.dataViewer",
    "roles/bigquery.jobUser",
    "roles/aiplatform.user",
    "roles/pubsub.subscriber"
  ])
  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.ai_analyst.email}"
}
