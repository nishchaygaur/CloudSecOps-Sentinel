output "detector_sa_email" {
  value       = google_service_account.detector.email
  description = "Email of the Detector Service Account"
}

output "remediator_sa_email" {
  value       = google_service_account.remediator.email
  description = "Email of the Remediator Service Account"
}

output "ai_analyst_sa_email" {
  value       = google_service_account.ai_analyst.email
  description = "Email of the AI Analyst Service Account"
}
