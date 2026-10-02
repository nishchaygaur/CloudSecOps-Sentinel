# -----------------------------------------------------------------------------
# 1. Primary Security Telemetry Topic & DLQ
# -----------------------------------------------------------------------------
resource "google_pubsub_topic" "dead_letter" {
  name    = "security-telemetry-dlq"
  project = var.project_id

  labels = {
    app  = "cloudsecops-sentinel"
    role = "dead-letter"
  }
}

resource "google_pubsub_topic" "telemetry" {
  name    = "cloud-security-telemetry"
  project = var.project_id

  labels = {
    app  = "cloudsecops-sentinel"
    role = "telemetry-stream"
  }
}

# -----------------------------------------------------------------------------
# 2. Critical Security Alerts Topic
# -----------------------------------------------------------------------------
resource "google_pubsub_topic" "alerts" {
  name    = "security-alerts-critical"
  project = var.project_id

  labels = {
    app  = "cloudsecops-sentinel"
    role = "incident-alerts"
  }
}

# -----------------------------------------------------------------------------
# 3. Pull Subscription for Detector Service (High Throughput & Retries)
# -----------------------------------------------------------------------------
resource "google_pubsub_subscription" "detector_subscription" {
  name    = "sub-detector-telemetry"
  topic   = google_pubsub_topic.telemetry.name
  project = var.project_id

  ack_deadline_seconds       = 30
  message_retention_duration = "604800s" # 7 days
  retain_acked_messages      = false

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }
}

# -----------------------------------------------------------------------------
# 4. Pull Subscription for Remediator & AI Analyst on Alerts
# -----------------------------------------------------------------------------
resource "google_pubsub_subscription" "remediator_subscription" {
  name    = "sub-remediator-alerts"
  topic   = google_pubsub_topic.alerts.name
  project = var.project_id

  ack_deadline_seconds = 60

  retry_policy {
    minimum_backoff = "5s"
    maximum_backoff = "60s"
  }
}
