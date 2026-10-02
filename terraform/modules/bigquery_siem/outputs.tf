output "dataset_id" {
  value       = google_bigquery_dataset.secops_siem.dataset_id
  description = "BigQuery dataset ID"
}

output "audit_events_table_id" {
  value       = google_bigquery_table.audit_events.table_id
  description = "Audit events table ID"
}

output "security_alerts_table_id" {
  value       = google_bigquery_table.security_alerts.table_id
  description = "Security alerts table ID"
}
