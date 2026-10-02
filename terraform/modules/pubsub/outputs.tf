output "telemetry_topic_id" {
  value       = google_pubsub_topic.telemetry.id
  description = "Resource ID of the telemetry Pub/Sub topic"
}

output "telemetry_topic_name" {
  value       = google_pubsub_topic.telemetry.name
  description = "Name of the telemetry Pub/Sub topic"
}

output "alerts_topic_id" {
  value       = google_pubsub_topic.alerts.id
  description = "Resource ID of the alerts Pub/Sub topic"
}

output "alerts_topic_name" {
  value       = google_pubsub_topic.alerts.name
  description = "Name of the alerts Pub/Sub topic"
}

output "detector_subscription_id" {
  value       = google_pubsub_subscription.detector_subscription.id
  description = "ID of the detector subscription"
}
