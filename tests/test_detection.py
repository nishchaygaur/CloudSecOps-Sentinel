import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("services/detector"))
from rules.engine import DetectionEngine
import attacks_simulator.simulate_threats as sim

def test_engine():
    engine = DetectionEngine()
    scenarios = sim.get_threat_scenarios("test-sentinel-gcp")
    
    print("\n" + "=" * 70)
    print("🧪 RUNNING CLOUDSECOPS SENTINEL DETECTION RULE VERIFICATION")
    print("=" * 70)
    
    passed = 0
    for sc in scenarios:
        raw_event = sc["event"]
        normalized = {
            "insert_id": raw_event.get("insertId"),
            "service_name": raw_event["protoPayload"]["serviceName"],
            "method_name": raw_event["protoPayload"]["methodName"],
            "principal_email": raw_event["protoPayload"]["authenticationInfo"]["principalEmail"],
            "caller_ip": raw_event["protoPayload"]["requestMetadata"]["callerIp"],
            "resource_name": raw_event["protoPayload"]["resourceName"],
            "request_payload": raw_event["protoPayload"]["request"]
        }
        
        alerts = engine.evaluate(normalized)
        
        if "Benign" in sc["name"]:
            assert len(alerts) == 0, f"Expected 0 alerts for benign event, got {len(alerts)}"
            print(f"✅ {sc['name']}: CORRECTLY PASSED AS BENIGN")
        else:
            assert len(alerts) >= 1, f"Expected alert for threat scenario {sc['name']}"
            alert = alerts[0]
            print(f"🚨 {sc['name']}:")
            print(f"   - Rule:     {alert.rule_id} ({alert.rule_name})")
            print(f"   - MITRE:    {alert.mitre_technique} [{alert.mitre_tactic}]")
            print(f"   - Severity: {alert.severity}")
            print(f"   - Action:   {alert.remediation_action}")
        passed += 1

    print("=" * 70)
    print(f"🎯 ALL {passed}/{len(scenarios)} TEST SCENARIOS PASSED WITH 100% ACCURACY!")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    test_engine()
