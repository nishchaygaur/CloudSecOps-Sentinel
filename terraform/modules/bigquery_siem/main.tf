resource "google_bigquery_dataset" "secops_siem" {
  dataset_id                  = "secops_siem"
  friendly_name               = "CloudSecOps Sentinel SIEM"
  description                 = "Security Data Lake storing partitioned audit logs and detected security alerts"
  location                    = var.region
  project                     = var.project_id
  delete_contents_on_destroy  = false

  labels = {
    env      = "production"
    app      = "cloudsecops-sentinel"
    function = "siem"
  }
}

# -----------------------------------------------------------------------------
# 1. Partitioned & Clustered Audit Events Table
# -----------------------------------------------------------------------------
resource "google_bigquery_table" "audit_events" {
  dataset_id          = google_bigquery_dataset.secops_siem.dataset_id
  table_id            = "audit_events"
  project             = var.project_id
  deletion_protection = false

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["principal_email", "service_name", "method_name", "severity"]

  schema = jsonencode([
    { name = "insert_id", type = "STRING", mode = "REQUIRED", description = "Unique log event ID" },
    { name = "timestamp", type = "TIMESTAMP", mode = "REQUIRED", description = "Event occurrence timestamp" },
    { name = "severity", type = "STRING", mode = "NULLABLE", description = "GCP severity level (INFO, NOTICE, WARNING, ERROR)" },
    { name = "principal_email", type = "STRING", mode = "NULLABLE", description = "Actor / Service account email" },
    { name = "caller_ip", type = "STRING", mode = "NULLABLE", description = "Source IP address" },
    { name = "user_agent", type = "STRING", mode = "NULLABLE", description = "Caller User Agent" },
    { name = "service_name", type = "STRING", mode = "NULLABLE", description = "GCP API service name" },
    { name = "method_name", type = "STRING", mode = "NULLABLE", description = "GCP API method invoked" },
    { name = "resource_name", type = "STRING", mode = "NULLABLE", description = "Target resource URI/name" },
    { name = "status_code", type = "INT64", mode = "NULLABLE", description = "HTTP or gRPC status code" },
    { name = "request_payload", type = "STRING", mode = "NULLABLE", description = "JSON request payload" },
    { name = "response_payload", type = "STRING", mode = "NULLABLE", description = "JSON response payload" },
    { name = "raw_json", type = "STRING", mode = "NULLABLE", description = "Complete raw log entry" }
  ])
}

# -----------------------------------------------------------------------------
# 2. Partitioned & Clustered Security Alerts Table
# -----------------------------------------------------------------------------
resource "google_bigquery_table" "security_alerts" {
  dataset_id          = google_bigquery_dataset.secops_siem.dataset_id
  table_id            = "security_alerts"
  project             = var.project_id
  deletion_protection = false

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["rule_id", "severity", "mitre_technique", "status"]

  schema = jsonencode([
    { name = "alert_id", type = "STRING", mode = "REQUIRED", description = "Unique alert ID (UUID)" },
    { name = "timestamp", type = "TIMESTAMP", mode = "REQUIRED", description = "Detection timestamp" },
    { name = "rule_id", type = "STRING", mode = "REQUIRED", description = "Detection rule identifier" },
    { name = "rule_name", type = "STRING", mode = "REQUIRED", description = "Descriptive rule title" },
    { name = "mitre_technique", type = "STRING", mode = "REQUIRED", description = "MITRE ATT&CK Technique ID" },
    { name = "mitre_tactic", type = "STRING", mode = "REQUIRED", description = "MITRE ATT&CK Tactic" },
    { name = "severity", type = "STRING", mode = "REQUIRED", description = "CRITICAL, HIGH, MEDIUM, LOW" },
    { name = "principal_email", type = "STRING", mode = "NULLABLE", description = "Offending principal" },
    { name = "caller_ip", type = "STRING", mode = "NULLABLE", description = "Offending IP address" },
    { name = "resource_affected", type = "STRING", mode = "NULLABLE", description = "Compromised or modified GCP resource" },
    { name = "description", type = "STRING", mode = "NULLABLE", description = "Details of the malicious action" },
    { name = "status", type = "STRING", mode = "REQUIRED", description = "DETECTED, REMEDIATED, INVESTIGATING, CLOSED" },
    { name = "remediation_action", type = "STRING", mode = "NULLABLE", description = "Automated SOAR containment action taken" },
    { name = "ai_incident_summary", type = "STRING", mode = "NULLABLE", description = "Gemini LLM generated post-mortem / brief" }
  ])
}
