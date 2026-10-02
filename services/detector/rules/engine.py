"""
MITRE ATT&CK Cloud Detection Rules Engine
Evaluates normalized Cloud Audit Logs against Cloud Security rules.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import uuid
from datetime import datetime, timezone

@dataclass
class ThreatAlert:
    alert_id: str
    timestamp: str
    rule_id: str
    rule_name: str
    mitre_technique: str
    mitre_tactic: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    principal_email: str
    caller_ip: str
    resource_affected: str
    description: str
    status: str  # DETECTED
    remediation_action: Optional[str] = None
    raw_event: Optional[Dict[str, Any]] = None

class DetectionEngine:
    def __init__(self, approved_regions: Optional[List[str]] = None):
        self.approved_regions = approved_regions or ["us-central1", "us-east1", "us-west1", "europe-west1"]

    def evaluate(self, event: Dict[str, Any]) -> List[ThreatAlert]:
        """
        Evaluates a normalized audit log event against all active MITRE rules.
        """
        alerts: List[ThreatAlert] = []
        
        service_name = event.get("service_name", "")
        method_name = event.get("method_name", "")
        principal = event.get("principal_email", "unknown")
        caller_ip = event.get("caller_ip", "0.0.0.0")
        resource = event.get("resource_name", "")
        req_payload = event.get("request_payload", {}) or {}
        now_iso = datetime.now(timezone.utc).isoformat()

        # ---------------------------------------------------------------------
        # Rule 1: T1098.001 - Additional Cloud Credentials (SA Key Creation)
        # ---------------------------------------------------------------------
        if "iam.googleapis.com" in service_name and "CreateServiceAccountKey" in method_name:
            alerts.append(ThreatAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=now_iso,
                rule_id="RULE-GCP-IAM-001",
                rule_name="Unauthorized Service Account Key Creation",
                mitre_technique="T1098.001",
                mitre_tactic="Persistence / Privilege Escalation",
                severity="CRITICAL",
                principal_email=principal,
                caller_ip=caller_ip,
                resource_affected=resource,
                description=f"Principal '{principal}' generated a new long-lived Service Account Key for resource '{resource}'. Long-lived keys bypass Workload Identity and risk credential exfiltration.",
                status="DETECTED",
                remediation_action="REVOKE_SERVICE_ACCOUNT_KEY",
                raw_event=event
            ))

        # ---------------------------------------------------------------------
        # Rule 2: T1078.004 - Cloud Privilege Escalation (Owner/Editor IAM Grant)
        # ---------------------------------------------------------------------
        if "SetIamPolicy" in method_name or "setIamPolicy" in method_name:
            bindings = req_payload.get("policy", {}).get("bindings", [])
            for binding in bindings:
                role = binding.get("role", "")
                if role in ["roles/owner", "roles/editor", "roles/resourcemanager.organizationAdmin"]:
                    members = binding.get("members", [])
                    alerts.append(ThreatAlert(
                        alert_id=str(uuid.uuid4()),
                        timestamp=now_iso,
                        rule_id="RULE-GCP-IAM-002",
                        rule_name="Critical IAM Privilege Escalation Grant",
                        mitre_technique="T1078.004",
                        mitre_tactic="Privilege Escalation",
                        severity="CRITICAL",
                        principal_email=principal,
                        caller_ip=caller_ip,
                        resource_affected=resource,
                        description=f"Principal '{principal}' granted administrative role '{role}' to members: {members} on resource '{resource}'.",
                        status="DETECTED",
                        remediation_action="ROLLBACK_IAM_GRANT",
                        raw_event=event
                    ))
                    break

        # ---------------------------------------------------------------------
        # Rule 3: T1530 - Cloud Storage Public Exposure (Data Exfiltration Risk)
        # ---------------------------------------------------------------------
        if "storage.googleapis.com" in service_name and ("setIamPermissions" in method_name or "update" in method_name):
            bindings = req_payload.get("bindings", []) or req_payload.get("policy", {}).get("bindings", [])
            is_public = False
            for b in bindings:
                for member in b.get("members", []):
                    if member in ["allUsers", "allAuthenticatedUsers"]:
                        is_public = True
                        break
            if is_public:
                alerts.append(ThreatAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=now_iso,
                    rule_id="RULE-GCP-GCS-001",
                    rule_name="Cloud Storage Bucket Made Publicly Accessible",
                    mitre_technique="T1530",
                    mitre_tactic="Exfiltration / Defense Evasion",
                    severity="CRITICAL",
                    principal_email=principal,
                    caller_ip=caller_ip,
                    resource_affected=resource,
                    description=f"Bucket '{resource}' was exposed to the public Internet ('allUsers' / 'allAuthenticatedUsers') by '{principal}'.",
                    status="DETECTED",
                    remediation_action="ENFORCE_PUBLIC_ACCESS_PREVENTION",
                    raw_event=event
                ))

        # ---------------------------------------------------------------------
        # Rule 4: T1562.001 - Impair Defenses (Log Sink Tampering)
        # ---------------------------------------------------------------------
        if "logging.googleapis.com" in service_name and ("DeleteSink" in method_name or "UpdateSink" in method_name):
            alerts.append(ThreatAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=now_iso,
                rule_id="RULE-GCP-LOG-001",
                rule_name="Audit Log Router Sink Tampering",
                mitre_technique="T1562.001",
                mitre_tactic="Defense Evasion",
                severity="HIGH",
                principal_email=principal,
                caller_ip=caller_ip,
                resource_affected=resource,
                description=f"Principal '{principal}' modified or deleted Cloud Logging Sink '{resource}', attempting to blind SIEM detection pipelines.",
                status="DETECTED",
                remediation_action="RECREATE_AUDIT_SINK",
                raw_event=event
            ))

        # ---------------------------------------------------------------------
        # Rule 5: T1496 - Resource Hijacking (Unauthorized Compute in Foreign Region)
        # ---------------------------------------------------------------------
        if "compute.googleapis.com" in service_name and "instances.insert" in method_name:
            zone = req_payload.get("zone", "")
            region = "-".join(zone.split("-")[:2]) if zone else ""
            if region and region not in self.approved_regions:
                alerts.append(ThreatAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=now_iso,
                    rule_id="RULE-GCP-GCE-001",
                    rule_name="Compute Provisioning in Unapproved Region",
                    mitre_technique="T1496",
                    mitre_tactic="Impact / Resource Hijacking",
                    severity="HIGH",
                    principal_email=principal,
                    caller_ip=caller_ip,
                    resource_affected=resource,
                    description=f"Instance created in foreign region '{region}' outside whitelist {self.approved_regions}. Potential crypto-mining or data exfiltration staging.",
                    status="DETECTED",
                    remediation_action="TERMINATE_ROGUE_INSTANCE",
                    raw_event=event
                ))

        return alerts
