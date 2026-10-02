output "project_id" {
  value       = var.project_id
  description = "The GCP project ID"
}

output "bigquery_dataset" {
  value       = module.bigquery_siem.dataset_id
  description = "BigQuery SIEM Dataset"
}

output "telemetry_topic" {
  value       = module.pubsub.telemetry_topic_name
  description = "Pub/Sub Telemetry Topic"
}

output "alerts_topic" {
  value       = module.pubsub.alerts_topic_name
  description = "Pub/Sub Security Alerts Topic"
}

output "detector_service_url" {
  value       = module.cloud_run.detector_url
  description = "Detector Cloud Run Service URL"
}

output "remediator_service_url" {
  value       = module.cloud_run.remediator_url
  description = "Remediator Cloud Run Service URL"
}

output "ai_analyst_service_url" {
  value       = module.cloud_run.ai_analyst_url
  description = "AI Analyst Cloud Run Service URL"
}
