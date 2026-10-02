variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "region" {
  type        = string
  description = "GCP Region for BigQuery dataset"
  default     = "us-central1"
}
