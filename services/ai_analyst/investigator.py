"""
CloudSecOps Sentinel - Gemini SecOps Incident Investigator
Performs context enrichment via BigQuery and synthesizes incident triage briefs with Gemini.
"""

import os
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger("secops-investigator")

class IncidentInvestigator:
    def __init__(self, project_id: str, dataset_id: str, model_name: str = "gemini-2.5-flash"):
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.model_name = model_name
        self.bq_client = None
        self.genai_client = None
        self._init_clients()

    def _init_clients(self):
        try:
            from google.cloud import bigquery
            self.bq_client = bigquery.Client(project=self.project_id)
        except Exception as e:
            logger.warning(f"BigQuery client unavailable: {e}")

        try:
            from google import genai
            # Uses GEMINI_API_KEY or Google Application Default Credentials
            self.genai_client = genai.Client()
            logger.info("Initialized Google GenAI client.")
        except Exception as e:
            logger.warning(f"GenAI client unavailable: {e}. Falling back to heuristic synthesis.")

    def fetch_principal_timeline(self, principal_email: str, limit: int = 15) -> List[Dict[str, Any]]:
        """
        Queries BigQuery for recent API calls executed by the offending principal.
        """
        if not self.bq_client or not principal_email or principal_email == "unknown":
            return []

        query = f"""
            SELECT timestamp, service_name, method_name, caller_ip, resource_name, status_code
            FROM `{self.project_id}.{self.dataset_id}.audit_events`
            WHERE principal_email = @principal
            ORDER BY timestamp DESC
            LIMIT {limit}
        """
        try:
            from google.cloud import bigquery
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("principal", "STRING", principal_email)
                ]
            )
            query_job = self.bq_client.query(query, job_config=job_config)
            return [dict(row) for row in query_job]
        except Exception as e:
            logger.error(f"Failed to query audit history from BigQuery: {e}")
            return []

    def generate_incident_brief(self, alert: Dict[str, Any], timeline: List[Dict[str, Any]]) -> str:
        """
        Uses Gemini 2.5 to analyze the alert context and generate a complete incident dossier.
        """
        prompt = f"""
You are an Elite Google Cloud Incident Responder & SecOps Analyst.
Analyze the following high-priority cloud security alert detected in Google Cloud Platform (GCP).

### ALERT DETAILS:
- Rule: {alert.get('rule_id')} - {alert.get('rule_name')}
- Severity: {alert.get('severity')}
- MITRE ATT&CK: {alert.get('mitre_technique')} ({alert.get('mitre_tactic')})
- Offending Principal: {alert.get('principal_email')}
- Caller IP: {alert.get('caller_ip')}
- Affected Resource: {alert.get('resource_affected')}
- Trigger Description: {alert.get('description')}
- Automated Action Taken: {alert.get('remediation_action')}

### RECENT ACTIVITY TIMELINE BY PRINCIPAL:
{json.dumps(timeline, indent=2, default=str) if timeline else "No prior history recorded in this window."}

### INSTRUCTIONS:
Generate a professional, structured Incident Response Triage Report in Markdown with the following sections:
1. 🚨 **Executive Incident Summary**: Clear, concise overview of what occurred and the immediate risk to cloud operations.
2. 🎯 **Threat Actor Profile & Attack Vector**: Analysis of the actor identity, IP reputation context, and access method.
3. 🗺️ **MITRE ATT&CK Cloud TTP Mapping**: Map the technique, tactical goal, and explain the adversarial objective.
4. 💥 **Blast Radius & Potential Impact**: What data or infrastructure is exposed or at risk?
5. 🛡️ **Containment & Remediation Verification**: Confirm whether the automated action was sufficient or if further containment is needed.
6. 📋 **SOC Analyst Action Checklist**: 3-5 prioritized, concrete steps for the security engineering team to execute next.
"""

        if self.genai_client:
            try:
                response = self.genai_client.models.generate_content(
                    model=self.model_name,
                    contents=prompt
                )
                return response.text
            except Exception as e:
                logger.error(f"Gemini API call failed: {e}. Using expert fallback.")

        # Expert Heuristic Fallback Dossier
        return f"""
# 🚨 Security Incident Triage Dossier (Automated SecOps Analysis)

## 1. Executive Incident Summary
At `{alert.get('timestamp')}`, CloudSecOps Sentinel flagged a **{alert.get('severity')}** security violation triggered by principal **`{alert.get('principal_email')}`**.
The event matches rule **{alert.get('rule_id')} ({alert.get('rule_name')})** indicating potential adversary activity or severe policy non-compliance on resource `{alert.get('resource_affected')}`.

## 2. Threat Actor & Attack Vector
- **Actor Identity**: `{alert.get('principal_email')}`
- **Source IP**: `{alert.get('caller_ip')}`
- **Attack Vector**: Direct GCP API call invoking `{alert.get('rule_name')}`.

## 3. MITRE ATT&CK Cloud Mapping
- **Technique**: `{alert.get('mitre_technique')}`
- **Tactic**: `{alert.get('mitre_tactic')}`
- **Adversary Objective**: Achieve cloud persistence, evade security visibility, or access sensitive cloud-hosted assets.

## 4. Blast Radius Assessment
- **Affected Asset**: `{alert.get('resource_affected')}`
- **Risk Level**: Critical. Potential unauthorized access or data exfiltration channel established.

## 5. Automated Containment Status
- **Automated Action**: `{alert.get('remediation_action') or 'NONE'}`
- **Status**: Dispatched to SOAR Remediator engine for immediate rollback.

## 6. SOC Analyst Action Checklist
1. [ ] Verify revocation of any generated credentials for `{alert.get('principal_email')}`.
2. [ ] Review Cloud Audit Logs in BigQuery for the caller IP `{alert.get('caller_ip')}` across all projects.
3. [ ] Confirm MFA / SSO status on the offending identity account.
4. [ ] Invalidate active session tokens for the affected user/service account.
"""
