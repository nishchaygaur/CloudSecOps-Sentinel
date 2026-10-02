# 🛡️ CloudSecOps Sentinel: Autonomous Cloud Detection & Response (CDIR / SOAR) on GCP

[![Google Cloud](https://img.shields.io/badge/Google_Cloud-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white)](https://cloud.google.com)
[![Terraform](https://img.shields.io/badge/Terraform-844FBA?style=for-the-badge&logo=terraform&logoColor=white)](https://terraform.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Cloud_Matrix-red?style=for-the-badge)](https://attack.mitre.org/matrices/enterprise/cloud/)
[![BigQuery](https://img.shields.io/badge/SIEM-BigQuery-blue?style=for-the-badge&logo=google-bigquery&logoColor=white)](https://cloud.google.com/bigquery)
[![Gemini](https://img.shields.io/badge/AI_Analyst-Gemini_2.5-8E75C2?style=for-the-badge&logo=google-gemini&logoColor=white)](https://deepmind.google/technologies/gemini/)

**CloudSecOps Sentinel** is an enterprise-grade, cloud-native Security Operations and Automated Incident Response (SOAR) platform engineered specifically for **Google Cloud Platform (GCP)**. 

It continuously monitors GCP infrastructure, evaluates audit telemetry against the **MITRE ATT&CK Cloud Matrix**, auto-remediates critical misconfigurations in milliseconds, maintains a security data lake in **BigQuery**, and uses **Google Gemini** as an autonomous SecOps investigator to generate structured incident triage dossiers.

---

## 🏗️ Architecture Overview

```
[ GCP Services / GKE / Cloud Run / IAM / Storage / VPC ]
                      │ (Admin Activity & System Events)
                      ▼
            [ Cloud Logging Log Sink ]
                      │ (Filtered Audit Stream)
                      ▼
       [ Cloud Pub/Sub: security-telemetry ]
                      │ (Push Subscription)
                      ▼
         [ Cloud Run: Detection Engine ] ───► [ BigQuery SIEM Data Lake ]
          (MITRE ATT&CK Rule Evaluation)      (Partitioned / Clustered Audit Events)
                      │
            Threat Detected?
            ├── [ YES: Severity = CRITICAL ] ──► [ Cloud Run: SOAR Auto-Remediator ]
            │                                     ├── Revoke Compromised Keys
            │                                     ├── Rollback Public Buckets
            │                                     └── Quarantine Compromised Roles
            │
            └── [ YES: Investigation Required ] ─► [ Cloud Run: Gemini AI SecOps Analyst ]
                                                  ├── Contextual Query to BigQuery
                                                  ├── Attack Chain Correlation
                                                  └── Generate Executive Post-Mortem
```

---

## 🎯 MITRE ATT&CK for Cloud Coverage

| Technique ID | Technique Name | Detection Signature | Automated Remediation (SOAR) |
| :--- | :--- | :--- | :--- |
| **T1098.001** | Account Manipulation: Additional Cloud Credentials | Creation of rogue Service Account Keys (`CreateServiceAccountKey`) | Automatically disables or deletes unauthorized service account key |
| **T1078.004** | Valid Accounts: Cloud Accounts | Unauthorized granting of `roles/owner` or `roles/editor` via `SetIamPolicy` | Rolls back unauthorized IAM role bindings to previous policy |
| **T1530** | Data from Cloud Storage Object | Storage bucket made publicly readable (`allUsers`, `allAuthenticatedUsers`) | Enforces Public Access Prevention and strips public IAM policies |
| **T1562.001** | Impair Defenses: Disable Cloud Logs | Deletion or modification of Cloud Logging Sinks or SCC exports | Re-provisions logging sinks and alerts SOC team immediately |
| **T1496** | Resource Hijacking | Compute instances provisioned in unapproved regions or sudden GPU surge | Terminates unauthorized instances and alerts platform admins |

---

## 🚀 Repository Structure

```
d:\Antigravity\GCP/
├── terraform/                   # 100% Modular Infrastructure as Code
│   ├── modules/
│   │   ├── audit_sinks/         # Exports Admin/Data audit logs to Pub/Sub
│   │   ├── pubsub/              # Event streaming queues & DLQs
│   │   ├── bigquery_siem/       # Partitioned security data warehouse & views
│   │   ├── detection_engine/    # Cloud Run detection service deployment
│   │   ├── soar_remediator/     # Cloud Run automated response service deployment
│   │   └── iam/                 # Least privilege custom roles & service accounts
│   ├── main.tf                  # Main Terraform configuration
│   ├── variables.tf             # Project, Region, and Environment variables
│   └── outputs.tf               # Deployed service URLs and resource IDs
├── services/
│   ├── detector/                # Real-time event parser & MITRE rule engine
│   │   ├── main.py              # FastAPI Webhook receiver for Pub/Sub push
│   │   ├── rules/               # Modular detection rule definitions
│   │   ├── bq_writer.py         # Streaming insert to BigQuery SIEM
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── remediator/              # SOAR automated response microservice
│   │   ├── main.py              # Remediation execution dispatcher
│   │   ├── actions/             # Safe rollback & containment actions
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   └── ai_analyst/              # Gemini 2.5 SecOps incident investigator
│       ├── main.py              # Triage engine
│       ├── investigator.py      # BQ correlation & LLM incident synthesis
│       ├── Dockerfile
│       └── requirements.txt
├── attacks_simulator/           # Safe CLI tool to simulate attacks for live demos
│   ├── simulate_threats.py      # Generates synthetic and live GCP audit events
│   └── test_payloads/           # Sample audit events for offline testing
├── .github/
│   └── workflows/
│       ├── terraform-deploy.yaml# CI/CD with Workload Identity Federation
│       └── services-build.yaml  # Artifact Registry container builds
└── README.md
```

---

## ⚡ Quickstart Deployment

### Prerequisites
- Google Cloud Account with an active Project ID
- `gcloud` CLI installed & authenticated (`gcloud auth login`)
- `terraform` v1.5+ installed

### 1. Set Your Project
```bash
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="us-central1"
gcloud config set project $GCP_PROJECT_ID
```

### 2. Deploy Infrastructure via Terraform
```bash
cd terraform
terraform init
terraform plan -var="project_id=$GCP_PROJECT_ID" -var="region=$GCP_REGION"
terraform apply -auto-approve -var="project_id=$GCP_PROJECT_ID" -var="region=$GCP_REGION"
```

### 3. Run the Threat Simulator
```bash
cd ../attacks_simulator
python simulate_threats.py --mode dry-run
```
