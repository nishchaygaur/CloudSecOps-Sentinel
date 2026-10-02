"""
CloudSecOps Sentinel - Detection Engine Service
FastAPI entrypoint receiving GCP Cloud Audit Logs via Pub/Sub Push or Webhook.
"""

import os
import json
import base64
import logging
from typing import Dict, Any, List
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import httpx

from rules.engine import DetectionEngine, ThreatAlert
from bq_writer import BigQueryWriter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel-detector")

app = FastAPI(
    title="CloudSecOps Sentinel - Detection Engine",
    description="Real-time MITRE ATT&CK Cloud Detection & SIEM Streaming",
    version="1.0.0"
)

PROJECT_ID = os.getenv("PROJECT_ID", "local-gcp-dev")
DATASET_ID = os.getenv("BQ_DATASET_ID", "secops_siem")
REMEDIATOR_URL = os.getenv("REMEDIATOR_URL", "http://localhost:8081/remediate")
AI_ANALYST_URL = os.getenv("AI_ANALYST_URL", "http://localhost:8082/triage")

engine = DetectionEngine()
bq_writer = BigQueryWriter(project_id=PROJECT_ID, dataset_id=DATASET_ID)

def normalize_audit_log(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts core fields from GCP Cloud Audit Log structure (protoPayload).
    """
    proto = payload.get("protoPayload", {})
    auth_info = proto.get("authenticationInfo", {})
    req_metadata = proto.get("requestMetadata", {})

    return {
        "insert_id": payload.get("insertId", ""),
        "timestamp": payload.get("timestamp", ""),
        "severity": payload.get("severity", "INFO"),
        "principal_email": auth_info.get("principalEmail", "anonymous"),
        "caller_ip": req_metadata.get("callerIp", "0.0.0.0"),
        "user_agent": req_metadata.get("callerSuppliedUserAgent", "unknown"),
        "service_name": proto.get("serviceName", ""),
        "method_name": proto.get("methodName", ""),
        "resource_name": proto.get("resourceName", ""),
        "status_code": proto.get("status", {}).get("code", 0),
        "request_payload": proto.get("request", {}),
        "response_payload": proto.get("response", {}),
        "raw_json": json.dumps(payload)
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "sentinel-detector",
        "project": PROJECT_ID,
        "dataset": DATASET_ID
    }

@app.post("/pubsub/push")
async def handle_pubsub_push(request: Request):
    """
    Handles Pub/Sub Push Subscription delivery format:
    {"message": {"data": "<base64>", "messageId": "..."}}
    """
    try:
        body = await request.json()
        message = body.get("message", {})
        data_b64 = message.get("data", "")
        if not data_b64:
            raise HTTPException(status_code=400, detail="Missing PubSub message data")

        raw_str = base64.b64decode(data_b64).decode("utf-8")
        payload = json.loads(raw_str)
        return await process_audit_event(payload)

    except Exception as e:
        logger.error(f"Error handling PubSub push: {e}", exc_info=True)
        # Return 200 to prevent infinite pubsub redelivery if payload is malformed
        return JSONResponse(status_code=200, content={"status": "error", "error": str(e)})

@app.post("/events/ingest")
async def ingest_direct_event(event: Dict[str, Any]):
    """
    Direct HTTP ingestion endpoint for testing and threat simulations.
    """
    return await process_audit_event(event)

async def process_audit_event(raw_event: Dict[str, Any]):
    normalized = normalize_audit_log(raw_event)
    logger.info(f"Processing event: {normalized['method_name']} by {normalized['principal_email']}")

    # 1. Stream into BigQuery SIEM
    bq_writer.insert_audit_event(normalized)

    # 2. Evaluate against MITRE ATT&CK Cloud Detection Rules
    alerts = engine.evaluate(normalized)
    
    response_data = {
        "status": "processed",
        "event_id": normalized["insert_id"],
        "alerts_count": len(alerts),
        "alerts": []
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        for alert in alerts:
            logger.warning(f"🚨 THREAT DETECTED: [{alert.severity}] {alert.rule_id} - {alert.rule_name}")
            alert_dict = {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "mitre_technique": alert.mitre_technique,
                "mitre_tactic": alert.mitre_tactic,
                "severity": alert.severity,
                "principal_email": alert.principal_email,
                "caller_ip": alert.caller_ip,
                "resource_affected": alert.resource_affected,
                "description": alert.description,
                "status": alert.status,
                "remediation_action": alert.remediation_action
            }

            # 3. Store alert in BigQuery
            bq_writer.insert_alert(alert_dict)
            response_data["alerts"].append(alert_dict)

            # 4. Trigger Automated SOAR Remediator (if critical)
            if alert.severity == "CRITICAL" and alert.remediation_action:
                try:
                    logger.info(f"Triggering auto-remediation for alert {alert.alert_id}")
                    await client.post(REMEDIATOR_URL, json=alert_dict)
                except Exception as rem_err:
                    logger.error(f"Failed to invoke Remediator: {rem_err}")

            # 5. Trigger Gemini AI SecOps Incident Analyst
            try:
                logger.info(f"Dispatching alert to Gemini AI Analyst: {alert.alert_id}")
                await client.post(AI_ANALYST_URL, json=alert_dict)
            except Exception as ai_err:
                logger.error(f"Failed to invoke AI Analyst: {ai_err}")

    return response_data
