output "sink_name" {
  value       = google_logging_project_sink.audit_sink.name
  description = "Name of the created audit log sink"
}

output "sink_writer_identity" {
  value       = google_logging_project_sink.audit_sink.writer_identity
  description = "Service account identity assigned to the sink"
}
