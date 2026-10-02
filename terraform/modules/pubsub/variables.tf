variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "detector_service_account" {
  type        = string
  description = "Service account email for Detector service"
}

variable "remediator_service_account" {
  type        = string
  description = "Service account email for Remediator service"
}
