"""
CloudSecOps Sentinel - Automated SOAR Remediator Service
FastAPI entrypoint executing automated containment and rollback actions.
"""

import os
import logging
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from actions.containment import (
    revoke_service_account_key,
    enforce_public_access_prevention,
    rollback_iam_grant
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel-remediator")

app = FastAPI(
    title="CloudSecOps Sentinel - Auto-Remediator (SOAR)",
    description="Automated Containment and Policy Rollback for Google Cloud",
    version="1.0.0"
)

PROJECT_ID = os.getenv("PROJECT_ID", "local-gcp-dev")
DRY_RUN = os.getenv("REMEDIATION_DRY_RUN", "false").lower() == "true"

class RemediationRequest(BaseModel):
    alert_id: str
    rule_id: str
    remediation_action: str
    resource_affected: str
    principal_email: str
    severity: str

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "sentinel-remediator",
        "project": PROJECT_ID,
        "dry_run": DRY_RUN
    }

@app.post("/remediate")
async def execute_remediation(req: RemediationRequest):
    logger.info(f"Received remediation request: {req.remediation_action} for {req.resource_affected}")
    
    action = req.remediation_action
    result = {}

    if action == "REVOKE_SERVICE_ACCOUNT_KEY":
        result = revoke_service_account_key(req.resource_affected, dry_run=DRY_RUN)

    elif action == "ENFORCE_PUBLIC_ACCESS_PREVENTION":
        result = enforce_public_access_prevention(req.resource_affected, dry_run=DRY_RUN)

    elif action == "ROLLBACK_IAM_GRANT":
        result = rollback_iam_grant(PROJECT_ID, req.principal_email, req.resource_affected, dry_run=DRY_RUN)

    else:
        logger.warning(f"Unrecognized remediation action: {action}")
        return {
            "status": "SKIPPED",
            "reason": f"No automated handler defined for action: {action}",
            "alert_id": req.alert_id
        }

    return {
        "alert_id": req.alert_id,
        "action_taken": action,
        "result": result
    }
