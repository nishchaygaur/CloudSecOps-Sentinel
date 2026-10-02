variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "region" {
  type        = string
  description = "GCP Region for Cloud Run services"
  default     = "us-central1"
}

variable "detector_sa_email" {
  type        = string
  description = "Detector Service Account Email"
}

variable "remediator_sa_email" {
  type        = string
  description = "Remediator Service Account Email"
}

variable "ai_analyst_sa_email" {
  type        = string
  description = "AI Analyst Service Account Email"
}

variable "telemetry_topic_name" {
  type        = string
  description = "Name of the security telemetry Pub/Sub topic"
}

variable "alerts_topic_name" {
  type        = string
  description = "Name of the critical alerts Pub/Sub topic"
}

variable "bq_dataset_id" {
  type        = string
  description = "BigQuery dataset ID"
}
