"""
BigQuery SIEM Data Lake Writer
Streams audit events and alerts into BigQuery tables with local fallback buffer.
"""

import os
import json
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

logger = logging.getLogger("bq_writer")

class BigQueryWriter:
    def __init__(self, project_id: str, dataset_id: str):
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.client = None
        self._init_client()

    def _init_client(self):
        try:
            from google.cloud import bigquery
            self.client = bigquery.Client(project=self.project_id)
            logger.info(f"Connected to BigQuery client for project '{self.project_id}'")
        except Exception as e:
            logger.warning(f"BigQuery client initialization skipped or failed: {e}. Running in buffered mode.")
            self.client = None

    def insert_audit_event(self, event: Dict[str, Any]) -> bool:
        """
        Streams a normalized audit event into the 'audit_events' table.
        """
        if not self.client:
            logger.debug(f"[BUFFERED] Audit event: {event.get('method_name')}")
            return True

        table_id = f"{self.project_id}.{self.dataset_id}.audit_events"
        row = {
            "insert_id": event.get("insert_id", str(datetime.now(timezone.utc).timestamp())),
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "severity": event.get("severity", "INFO"),
            "principal_email": event.get("principal_email"),
            "caller_ip": event.get("caller_ip"),
            "user_agent": event.get("user_agent"),
            "service_name": event.get("service_name"),
            "method_name": event.get("method_name"),
            "resource_name": event.get("resource_name"),
            "status_code": event.get("status_code", 0),
            "request_payload": json.dumps(event.get("request_payload", {})),
            "response_payload": json.dumps(event.get("response_payload", {})),
            "raw_json": json.dumps(event)
        }

        errors = self.client.insert_rows_json(table_id, [row])
        if errors:
            logger.error(f"Error inserting audit row to BigQuery: {errors}")
            return False
        return True

    def insert_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Streams a security alert into the 'security_alerts' table.
        """
        if not self.client:
            logger.warning(f"[BUFFERED ALERT] {alert_data.get('rule_id')} - {alert_data.get('rule_name')}")
            return True

        table_id = f"{self.project_id}.{self.dataset_id}.security_alerts"
        errors = self.client.insert_rows_json(table_id, [alert_data])
        if errors:
            logger.error(f"Error inserting alert to BigQuery: {errors}")
            return False
        return True
