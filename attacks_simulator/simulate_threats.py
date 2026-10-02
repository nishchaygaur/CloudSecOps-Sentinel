#!/usr/bin/env python3
"""
CloudSecOps Sentinel - MITRE ATT&CK Threat Simulator & Demo Runner
Generates realistic Google Cloud Audit Log events to demonstrate detection,
automated SOAR containment, and Gemini AI triage live.
"""

import sys
import time
import json
import uuid
import argparse
from datetime import datetime, timezone
import urllib.request
import urllib.error

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

def create_base_audit_event(service_name: str, method_name: str, principal: str, resource: str, caller_ip: str = "198.51.100.45", request_data: dict = None) -> dict:
    return {
        "insertId": f"audit-sim-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": "NOTICE",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": service_name,
            "methodName": method_name,
            "resourceName": resource,
            "authenticationInfo": {
                "principalEmail": principal
            },
            "requestMetadata": {
                "callerIp": caller_ip,
                "callerSuppliedUserAgent": "google-cloud-sdk gcloud/587.0.0 python/3.11"
            },
            "status": {
                "code": 0
            },
            "request": request_data or {},
            "response": {}
        }
    }

def get_threat_scenarios(project_id: str) -> list:
    return [
        {
            "id": "SCENARIO-1",
            "name": "MITRE T1098.001: Rogue Service Account Key Creation",
            "description": "Adversary generates a permanent offline private key to maintain persistent access.",
            "event": create_base_audit_event(
                service_name="iam.googleapis.com",
                method_name="google.iam.admin.v1.CreateServiceAccountKey",
                principal="attacker-shadow@malicious-domain.com",
                resource=f"projects/{project_id}/serviceAccounts/compute-engine-sa@{project_id}.iam.gserviceaccount.com/keys/key-{uuid.uuid4().hex[:8]}",
                caller_ip="203.0.113.195",
                request_data={"keyType": "TYPE_GOOGLE_CREDENTIALS_FILE"}
            )
        },
        {
            "id": "SCENARIO-2",
            "name": "MITRE T1078.004: Cloud Privilege Escalation (Owner Role Grant)",
            "description": "Compromised account attempts to grant 'roles/owner' to an external personal email.",
            "event": create_base_audit_event(
                service_name="cloudresourcemanager.googleapis.com",
                method_name="SetIamPolicy",
                principal="insider-compromised@company.com",
                resource=f"projects/{project_id}",
                caller_ip="198.51.100.88",
                request_data={
                    "policy": {
                        "bindings": [
                            {
                                "role": "roles/owner",
                                "members": ["user:attacker-exfil@gmail.com"]
                            }
                        ]
                    }
                }
            )
        },
        {
            "id": "SCENARIO-3",
            "name": "MITRE T1530: Cloud Storage Bucket Made Public (Data Exfiltration)",
            "description": "Misconfigured or adversary-controlled bucket opened to 'allUsers' on the internet.",
            "event": create_base_audit_event(
                service_name="storage.googleapis.com",
                method_name="storage.setIamPermissions",
                principal="dev-ops-temp@company.com",
                resource=f"projects/_/buckets/{project_id}-customer-financial-records",
                caller_ip="192.0.2.14",
                request_data={
                    "bindings": [
                        {
                            "role": "roles/storage.objectViewer",
                            "members": ["allUsers"]
                        }
                    ]
                }
            )
        },
        {
            "id": "SCENARIO-4",
            "name": "MITRE T1562.001: Impair Defenses (Deleting Audit Log Router Sink)",
            "description": "Attacker deletes Cloud Logging Sink to blind SIEM and evade forensic detection.",
            "event": create_base_audit_event(
                service_name="logging.googleapis.com",
                method_name="google.logging.v2.ConfigServiceV2.DeleteSink",
                principal="stealth-actor@dark-ops.net",
                resource=f"projects/{project_id}/sinks/sink-sentinel-audit-telemetry",
                caller_ip="45.33.32.156",
                request_data={"sinkName": "sink-sentinel-audit-telemetry"}
            )
        },
        {
            "id": "SCENARIO-5",
            "name": "Benign Baseline: Routine Read Operation (No False Positive)",
            "description": "Authorized developer listing storage buckets during normal workday.",
            "event": create_base_audit_event(
                service_name="storage.googleapis.com",
                method_name="storage.buckets.list",
                principal="engineer-alice@company.com",
                resource=f"projects/{project_id}",
                caller_ip="10.0.1.25",
                request_data={}
            )
        }
    ]

def send_event(target_url: str, event: dict):
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(
        target_url,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
            return result
    except urllib.error.URLError as e:
        return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description="CloudSecOps Sentinel Threat Simulator")
    parser.add_argument("--project", default="demo-sentinel-gcp", help="GCP Project ID")
    parser.add_argument("--target", default="http://localhost:8080/events/ingest", help="Target Ingestion Endpoint")
    parser.add_argument("--scenario", type=int, choices=[1, 2, 3, 4, 5], help="Run a specific scenario (1-5)")
    args = parser.parse_args()

    scenarios = get_threat_scenarios(args.project)
    
    if args.scenario:
        selected = [scenarios[args.scenario - 1]]
    else:
        selected = scenarios

    print("=" * 80)
    print("🛡️  CLOUDSECOPS SENTINEL — MITRE ATT&CK THREAT SIMULATION")
    print(f"🎯 Target Endpoint: {args.target}")
    print(f"🏢 Simulated Project: {args.project}")
    print("=" * 80)

    for sc in selected:
        print(f"\n▶ Executing: {sc['name']}")
        print(f"  Description: {sc['description']}")
        print(f"  Principal:   {sc['event']['protoPayload']['authenticationInfo']['principalEmail']}")
        print(f"  Method:      {sc['event']['protoPayload']['methodName']}")
        
        result = send_event(args.target, sc['event'])
        
        if "error" in result:
            print(f"  ❌ Transmission Failed: {result['error']}")
            print("     (Make sure sentinel-detector is running on http://localhost:8080)")
        else:
            alerts_count = result.get("alerts_count", 0)
            if alerts_count > 0:
                print(f"  🚨 DETECTED! {alerts_count} Security Alert(s) Generated:")
                for al in result.get("alerts", []):
                    print(f"     - [{al['severity']}] {al['rule_id']}: {al['rule_name']}")
                    print(f"       Action: {al.get('remediation_action', 'NONE')} | MITRE: {al['mitre_technique']}")
            else:
                print("  ✅ Event Passed: Classified as benign (0 alerts triggered).")

        time.sleep(1)

    print("\n" + "=" * 80)
    print("🏁 Simulation sequence finished.")
    print("=" * 80)

if __name__ == "__main__":
    main()
