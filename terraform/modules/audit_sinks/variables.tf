variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "pubsub_topic" {
  type        = string
  description = "Full resource ID of the target Pub/Sub topic"
}
