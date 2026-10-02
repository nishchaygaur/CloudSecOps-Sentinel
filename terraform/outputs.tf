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
  value       = var.enable_cloud_run ? module.cloud_run[0].detector_url : "Local/Docker (Cloud Run disabled without billing)"
  description = "Detector Cloud Run Service URL"
}

output "remediator_service_url" {
  value       = var.enable_cloud_run ? module.cloud_run[0].remediator_url : "Local/Docker (Cloud Run disabled without billing)"
  description = "Remediator Cloud Run Service URL"
}

output "ai_analyst_service_url" {
  value       = var.enable_cloud_run ? module.cloud_run[0].ai_analyst_url : "Local/Docker (Cloud Run disabled without billing)"
  description = "AI Analyst Cloud Run Service URL"
}
