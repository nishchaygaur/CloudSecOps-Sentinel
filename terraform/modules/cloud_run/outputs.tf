output "detector_url" {
  value       = google_cloud_run_v2_service.detector.uri
  description = "URI of the Detector Cloud Run service"
}

output "remediator_url" {
  value       = google_cloud_run_v2_service.remediator.uri
  description = "URI of the Remediator Cloud Run service"
}

output "ai_analyst_url" {
  value       = google_cloud_run_v2_service.ai_analyst.uri
  description = "URI of the AI Analyst Cloud Run service"
}
