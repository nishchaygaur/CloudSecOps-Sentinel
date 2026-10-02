variable "project_id" {
  description = "The GCP Project ID where resources will be deployed"
  type        = string
}

variable "region" {
  description = "The primary Google Cloud region for serverless compute and storage"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment name (e.g. dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "alert_notification_email" {
  description = "Email address to receive critical security incident alerts"
  type        = string
  default     = "security-alerts@example.com"
}
