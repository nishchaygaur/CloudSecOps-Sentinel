# -----------------------------------------------------------------------------
# 1. Detection Engine Service
# -----------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "detector" {
  name     = "sentinel-detector"
  location = var.region
  project  = var.project_id

  template {
    service_account = var.detector_sa_email

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }

    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello" # Placeholder until first container build

      resources {
        limits = {
          cpu    = "1000m"
          memory = "512Mi"
        }
      }

      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "BQ_DATASET_ID"
        value = var.bq_dataset_id
      }
      env {
        name  = "ALERTS_TOPIC"
        value = var.alerts_topic_name
      }
      env {
        name  = "ENVIRONMENT"
        value = "production"
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image
    ]
  }
}

# -----------------------------------------------------------------------------
# 2. Automated SOAR Remediator Service
# -----------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "remediator" {
  name     = "sentinel-remediator"
  location = var.region
  project  = var.project_id

  template {
    service_account = var.remediator_sa_email

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"

      resources {
        limits = {
          cpu    = "1000m"
          memory = "512Mi"
        }
      }

      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "BQ_DATASET_ID"
        value = var.bq_dataset_id
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image
    ]
  }
}

# -----------------------------------------------------------------------------
# 3. Gemini AI SecOps Incident Analyst Service
# -----------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "ai_analyst" {
  name     = "sentinel-ai-analyst"
  location = var.region
  project  = var.project_id

  template {
    service_account = var.ai_analyst_sa_email

    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }

    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"

      resources {
        limits = {
          cpu    = "1000m"
          memory = "1Gi"
        }
      }

      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "BQ_DATASET_ID"
        value = var.bq_dataset_id
      }
      env {
        name  = "GEMINI_MODEL"
        value = "gemini-2.5-flash"
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image
    ]
  }
}
