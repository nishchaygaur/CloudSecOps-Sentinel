"""
CloudSecOps Sentinel - Gemini AI SecOps Incident Analyst Service
FastAPI entrypoint receiving incident alerts, querying BigQuery timeline, and synthesizing reports.
"""

import os
import logging
from typing import Dict, Any
from fastapi import FastAPI
from pydantic import BaseModel

from investigator import IncidentInvestigator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel-ai-analyst")

app = FastAPI(
    title="CloudSecOps Sentinel - Gemini AI Incident Analyst",
    description="Autonomous SecOps Triage & MITRE ATT&CK Post-Mortem Generator",
    version="1.0.0"
)

PROJECT_ID = os.getenv("PROJECT_ID", "local-gcp-dev")
DATASET_ID = os.getenv("BQ_DATASET_ID", "secops_siem")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

investigator = IncidentInvestigator(
    project_id=PROJECT_ID,
    dataset_id=DATASET_ID,
    model_name=GEMINI_MODEL
)

class TriageRequest(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    mitre_technique: str
    mitre_tactic: str
    severity: str
    principal_email: str
    caller_ip: str
    resource_affected: str
    description: str
    remediation_action: str = ""

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "sentinel-ai-analyst",
        "project": PROJECT_ID,
        "dataset": DATASET_ID,
        "model": GEMINI_MODEL
    }

@app.post("/triage")
async def triage_incident(req: TriageRequest):
    logger.info(f"Initiating AI triage for alert {req.alert_id} ({req.rule_name})")

    # 1. Fetch recent activity timeline from BigQuery
    timeline = investigator.fetch_principal_timeline(req.principal_email, limit=10)

    # 2. Synthesize incident dossier via Gemini
    brief_markdown = investigator.generate_incident_brief(req.model_dump(), timeline)

    logger.info(f"Successfully generated incident triage report for {req.alert_id}")

    return {
        "alert_id": req.alert_id,
        "status": "TRIAGED",
        "dossier": brief_markdown,
        "timeline_events_analyzed": len(timeline)
    }
