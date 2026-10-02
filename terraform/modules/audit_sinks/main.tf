# -----------------------------------------------------------------------------
# Cloud Logging Log Router Sink for Audit Logs
# Filters all Cloud Audit Logs (Admin Activity, Policy Changes, Data Access)
# -----------------------------------------------------------------------------
resource "google_logging_project_sink" "audit_sink" {
  name        = "sink-sentinel-audit-telemetry"
  project     = var.project_id
  destination = "pubsub.googleapis.com/${var.pubsub_topic}"

  # Filter for all Google Cloud Audit Logs
  filter = "protoPayload.@type=\"type.googleapis.com/google.cloud.audit.AuditLog\""

  unique_writer_identity = true
}

# Grant the Sink's Service Account publisher rights to the Pub/Sub topic
resource "google_pubsub_topic_iam_member" "sink_publisher" {
  project = var.project_id
  topic   = var.pubsub_topic
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.audit_sink.writer_identity
}
