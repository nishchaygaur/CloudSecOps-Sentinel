import React, { useState } from 'react';
import { 
  Shield, 
  Terminal, 
  Database, 
  Cpu, 
  AlertTriangle, 
  CheckCircle, 
  ExternalLink, 
  Play, 
  RefreshCw, 
  Server, 
  Lock, 
  Eye, 
  Zap,
  Activity,
  ChevronRight,
  Sparkles,
  Layers,
  ArrowUpRight
} from 'lucide-react';

interface Scenario {
  id: string;
  title: string;
  mitre: string;
  tactic: string;
  severity: 'CRITICAL' | 'HIGH' | 'LOW';
  principal: string;
  callerIp: string;
  method: string;
  resource: string;
  action: string;
  description: string;
  rawJson: any;
  aiReport: {
    executive: string;
    actor: string;
    blastRadius: string;
    containment: string;
    checklist: string[];
  };
}

const SCENARIOS: Scenario[] = [
  {
    id: 'SCENARIO-1',
    title: 'Rogue Service Account Key Creation',
    mitre: 'T1098.001',
    tactic: 'Persistence / Privilege Escalation',
    severity: 'CRITICAL',
    principal: 'attacker-shadow@malicious-domain.com',
    callerIp: '203.0.113.195',
    method: 'google.iam.admin.v1.CreateServiceAccountKey',
    resource: 'projects/financial-automation-data/serviceAccounts/compute-engine-sa@financial-automation-data.iam.gserviceaccount.com/keys/key-8f7d9a1c',
    action: 'REVOKE_SERVICE_ACCOUNT_KEY',
    description: 'Adversary generated a permanent offline private key for compute-engine-sa to bypass Workload Identity and maintain persistent cloud access.',
    rawJson: {
      insertId: 'audit-sim-8f7d9a1c0001',
      severity: 'NOTICE',
      protoPayload: {
        serviceName: 'iam.googleapis.com',
        methodName: 'google.iam.admin.v1.CreateServiceAccountKey',
        resourceName: 'projects/financial-automation-data/serviceAccounts/compute-engine-sa@financial-automation-data.iam.gserviceaccount.com/keys/key-8f7d9a1c',
        authenticationInfo: { principalEmail: 'attacker-shadow@malicious-domain.com' },
        requestMetadata: { callerIp: '203.0.113.195', callerSuppliedUserAgent: 'gcloud/587.0.0 python/3.11' }
      }
    },
    aiReport: {
      executive: 'At 00:32 UTC, CloudSecOps Sentinel flagged a CRITICAL persistence attempt. An unauthorized external identity generated an offline Service Account credential file for a core workload service account.',
      actor: 'Actor is operating from external IP 203.0.113.195 using gcloud CLI. Pattern suggests compromised developer token being leveraged to plant persistent backdoors.',
      blastRadius: 'Targeted account possesses compute instance management permissions. If uncontained, could lead to rogue VM provisioning or cluster takeover.',
      containment: 'Automated SOAR Remediator executed in 118ms: The newly created key was permanently deleted via Google IAM API.',
      checklist: [
        'Invalidate active session tokens for attacker-shadow@malicious-domain.com',
        'Audit all Compute Engine instances for rogue SSH metadata injection',
        'Verify IAM policy conditions on compute-engine-sa',
        'Enable Organization Policy constraint constraints/iam.disableServiceAccountKeyCreation'
      ]
    }
  },
  {
    id: 'SCENARIO-2',
    title: 'Cloud Privilege Escalation (Owner Role Grant)',
    mitre: 'T1078.004',
    tactic: 'Privilege Escalation',
    severity: 'CRITICAL',
    principal: 'insider-compromised@company.com',
    callerIp: '198.51.100.88',
    method: 'SetIamPolicy',
    resource: 'projects/financial-automation-data',
    action: 'ROLLBACK_IAM_GRANT',
    description: 'Compromised identity granted administrative role roles/owner to an external unauthorized Gmail address.',
    rawJson: {
      insertId: 'audit-sim-e9b204fa0002',
      severity: 'WARNING',
      protoPayload: {
        serviceName: 'cloudresourcemanager.googleapis.com',
        methodName: 'SetIamPolicy',
        resourceName: 'projects/financial-automation-data',
        authenticationInfo: { principalEmail: 'insider-compromised@company.com' },
        request: {
          policy: {
            bindings: [{ role: 'roles/owner', members: ['user:attacker-exfil@gmail.com'] }]
          }
        }
      }
    },
    aiReport: {
      executive: 'High-severity privilege escalation detected. An internal account modified project-level IAM bindings to grant full owner permissions to an untrusted Gmail account.',
      actor: 'Originating from 198.51.100.88. Highly indicative of credential stuffing or an active insider threat.',
      blastRadius: 'Total project control across all BigQuery datasets, Cloud Storage buckets, and serverless compute.',
      containment: 'Automated SOAR Remediator revoked the roles/owner binding immediately upon event receipt in 144ms.',
      checklist: [
        'Lock and disable user account insider-compromised@company.com immediately',
        'Confirm revocation of attacker-exfil@gmail.com from Google Cloud IAM',
        'Review Cloud Audit Logs in BigQuery for other IAM grants executed within the last 48 hours'
      ]
    }
  },
  {
    id: 'SCENARIO-3',
    title: 'Cloud Storage Bucket Made Public (Data Exfiltration)',
    mitre: 'T1530',
    tactic: 'Exfiltration / Defense Evasion',
    severity: 'CRITICAL',
    principal: 'devops-contractor@company.com',
    callerIp: '192.0.2.14',
    method: 'storage.setIamPermissions',
    resource: 'projects/_/buckets/financial-automation-data-records',
    action: 'ENFORCE_PUBLIC_ACCESS_PREVENTION',
    description: 'Bucket containing sensitive data was exposed to allUsers on the public internet.',
    rawJson: {
      insertId: 'audit-sim-74d110ab0003',
      severity: 'ERROR',
      protoPayload: {
        serviceName: 'storage.googleapis.com',
        methodName: 'storage.setIamPermissions',
        resourceName: 'projects/_/buckets/financial-automation-data-records',
        authenticationInfo: { principalEmail: 'devops-contractor@company.com' },
        request: {
          bindings: [{ role: 'roles/storage.objectViewer', members: ['allUsers'] }]
        }
      }
    },
    aiReport: {
      executive: 'Critical data leak vector prevented. Cloud storage bucket containing financial telemetry was opened to anonymous worldwide access.',
      actor: 'Executed by devops-contractor@company.com from 192.0.2.14. Likely accidental misconfiguration or intentional exfiltration staging.',
      blastRadius: 'All objects stored in financial-automation-data-records were momentarily readable unauthenticated.',
      containment: 'SOAR Remediator enforced Public Access Prevention and stripped all public IAM members in 129ms.',
      checklist: [
        'Confirm public_access_prevention is enforced on all storage buckets in BigQuery',
        'Enable VPC Service Controls perimeter around Cloud Storage',
        'Review Cloud Storage access logs to check if any objects were downloaded during exposure window'
      ]
    }
  },
  {
    id: 'SCENARIO-4',
    title: 'Audit Log Router Sink Tampering (Defense Evasion)',
    mitre: 'T1562.001',
    tactic: 'Defense Evasion',
    severity: 'HIGH',
    principal: 'stealth-actor@dark-ops.net',
    callerIp: '45.33.32.156',
    method: 'google.logging.v2.ConfigServiceV2.DeleteSink',
    resource: 'projects/financial-automation-data/sinks/sink-sentinel-audit-telemetry',
    action: 'RECREATE_AUDIT_SINK',
    description: 'Adversary deleted Cloud Logging Sink to blind SIEM and evade forensic detection.',
    rawJson: {
      insertId: 'audit-sim-419bcf820004',
      severity: 'CRITICAL',
      protoPayload: {
        serviceName: 'logging.googleapis.com',
        methodName: 'google.logging.v2.ConfigServiceV2.DeleteSink',
        resourceName: 'projects/financial-automation-data/sinks/sink-sentinel-audit-telemetry',
        authenticationInfo: { principalEmail: 'stealth-actor@dark-ops.net' }
      }
    },
    aiReport: {
      executive: 'Defense evasion maneuver intercepted. Attacker attempted to sever telemetry flow from Cloud Logging to the Sentinel Pub/Sub pipeline.',
      actor: 'Actor is using proxy IP 45.33.32.156. Indicates experienced cloud adversary attempting anti-forensics.',
      blastRadius: 'Potential blind spot for subsequent actions across all Google Cloud services.',
      containment: 'Alert forwarded to SOC team with emergency priority; Terraform state drift detector triggered for sink re-provisioning.',
      checklist: [
        'Verify integrity of Cloud Logging Router Sinks and Pub/Sub pipelines',
        'Check BigQuery SIEM audit_events for any gap in log timestamps',
        'Isolate compromised credentials associated with stealth-actor@dark-ops.net'
      ]
    }
  },
  {
    id: 'SCENARIO-5',
    title: 'Benign Baseline: Routine Read Operation',
    mitre: 'Baseline',
    tactic: 'Normal Activity',
    severity: 'LOW',
    principal: 'engineer-alice@company.com',
    callerIp: '10.0.1.25',
    method: 'storage.buckets.list',
    resource: 'projects/financial-automation-data',
    action: 'NONE (0 FALSE POSITIVES)',
    description: 'Authorized engineer listing cloud storage buckets during normal workday. Correctly recognized as non-malicious.',
    rawJson: {
      insertId: 'audit-sim-110022330005',
      severity: 'INFO',
      protoPayload: {
        serviceName: 'storage.googleapis.com',
        methodName: 'storage.buckets.list',
        resourceName: 'projects/financial-automation-data',
        authenticationInfo: { principalEmail: 'engineer-alice@company.com' }
      }
    },
    aiReport: {
      executive: 'Standard administrative API read operation. Verified benign baseline.',
      actor: 'Authorized internal engineer operating from internal IP space 10.0.1.25.',
      blastRadius: 'Zero impact. Read-only metadata query.',
      containment: 'No containment action needed. Logged to BigQuery SIEM for compliance.',
      checklist: [
        'Normal baseline behavior recorded in audit_events table.'
      ]
    }
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState<'simulator' | 'ai' | 'bigquery' | 'architecture'>('simulator');
  const [selectedScenario, setSelectedScenario] = useState<Scenario>(SCENARIOS[0]);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulatedEvents, setSimulatedEvents] = useState<Scenario[]>([SCENARIOS[0]]);

  const handleSimulate = (scenario: Scenario) => {
    setSelectedScenario(scenario);
    setIsSimulating(true);
    setTimeout(() => {
      setIsSimulating(false);
      if (!simulatedEvents.some(e => e.id === scenario.id)) {
        setSimulatedEvents([scenario, ...simulatedEvents]);
      }
    }, 600);
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100 flex flex-col">
      {/* Top Banner */}
      <header className="border-b border-gray-800 bg-[#111827]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-sky-400 via-indigo-300 to-emerald-400 bg-clip-text text-transparent">
                  CloudSecOps Sentinel
                </span>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-sky-950 text-sky-400 border border-sky-800/60">
                  GCP CDIR / SOAR
                </span>
              </div>
              <p className="text-xs text-gray-400">Autonomous Cloud Detection & Response Platform</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-gray-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              GCP: <span className="text-sky-400 font-semibold">financial-automation-data</span>
              <span className="text-gray-600">|</span>
              Region: <span className="text-gray-400">us-central1</span>
            </div>

            <a
              href="https://github.com/nishchaygaur/CloudSecOps-Sentinel"
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 transition text-gray-200 border border-gray-700"
            >
              <span>GitHub</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-gray-400" />
            </a>
          </div>
        </div>
      </header>

      {/* Hero Stats */}
      <section className="bg-gradient-to-b from-[#111827]/40 to-transparent border-b border-gray-800/60">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-gray-900/60 border border-gray-800">
              <div className="flex items-center justify-between text-xs text-gray-400 font-medium mb-1">
                <span>Ingested Audit Events</span>
                <Activity className="w-4 h-4 text-sky-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-sky-400">18,429</div>
              <div className="text-[11px] text-emerald-400 flex items-center gap-1 mt-1 font-mono">
                <span>● Cloud Logging Sink Active</span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-gray-900/60 border border-gray-800">
              <div className="flex items-center justify-between text-xs text-gray-400 font-medium mb-1">
                <span>MITRE ATT&CK Rules</span>
                <Shield className="w-4 h-4 text-indigo-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-indigo-300">5 Rules</div>
              <div className="text-[11px] text-gray-400 font-mono mt-1">IAM, Storage, Logging, GCE</div>
            </div>

            <div className="p-4 rounded-xl bg-gray-900/60 border border-gray-800">
              <div className="flex items-center justify-between text-xs text-gray-400 font-medium mb-1">
                <span>Auto-Containment (SOAR)</span>
                <Zap className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-emerald-400">100%</div>
              <div className="text-[11px] text-gray-400 font-mono mt-1">Zero manual delay</div>
            </div>

            <div className="p-4 rounded-xl bg-gray-900/60 border border-gray-800">
              <div className="flex items-center justify-between text-xs text-gray-400 font-medium mb-1">
                <span>Mean Time to Contain</span>
                <Cpu className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-amber-400">132 ms</div>
              <div className="text-[11px] text-gray-400 font-mono mt-1">Automated serverless speed</div>
            </div>
          </div>
        </div>
      </section>

      {/* Nav Tabs */}
      <div className="border-b border-gray-800 bg-[#0B0F19]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex gap-1">
          <button
            onClick={() => setActiveTab('simulator')}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition ${
              activeTab === 'simulator'
                ? 'border-sky-500 text-sky-400 bg-sky-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Play className="w-4 h-4" />
            <span>Interactive Threat Simulator</span>
          </button>

          <button
            onClick={() => setActiveTab('ai')}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition ${
              activeTab === 'ai'
                ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Sparkles className="w-4 h-4" />
            <span>Gemini AI Incident Dossier</span>
          </button>

          <button
            onClick={() => setActiveTab('bigquery')}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition ${
              activeTab === 'bigquery'
                ? 'border-emerald-500 text-emerald-400 bg-emerald-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Database className="w-4 h-4" />
            <span>BigQuery SIEM Analytics</span>
          </button>

          <button
            onClick={() => setActiveTab('architecture')}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition ${
              activeTab === 'architecture'
                ? 'border-amber-500 text-amber-400 bg-amber-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>33 GCP Resources & Architecture</span>
          </button>
        </div>
      </div>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full">
        {/* TAB 1: THREAT SIMULATOR */}
        {activeTab === 'simulator' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            {/* Scenarios List */}
            <div className="lg:col-span-5 space-y-3">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-bold uppercase tracking-wider text-gray-400">
                  Select Attack Scenario to Simulate
                </h3>
                <span className="text-xs font-mono text-gray-500">5 Scenarios</span>
              </div>

              {SCENARIOS.map((sc) => (
                <div
                  key={sc.id}
                  onClick={() => setSelectedScenario(sc)}
                  className={`p-4 rounded-xl border cursor-pointer transition relative overflow-hidden ${
                    selectedScenario.id === sc.id
                      ? 'bg-gray-800/80 border-sky-500 shadow-md shadow-sky-500/10'
                      : 'bg-gray-900/60 border-gray-800 hover:border-gray-700 hover:bg-gray-800/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="text-xs font-mono font-bold text-sky-400 bg-sky-950 px-2 py-0.5 rounded border border-sky-800/60">
                      {sc.mitre}
                    </span>
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                        sc.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-400 border border-rose-800/60'
                          : sc.severity === 'HIGH'
                          ? 'bg-amber-950 text-amber-400 border border-amber-800/60'
                          : 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                      }`}
                    >
                      {sc.severity}
                    </span>
                  </div>

                  <h4 className="font-semibold text-sm text-gray-100 mb-1">{sc.title}</h4>
                  <p className="text-xs text-gray-400 line-clamp-2">{sc.description}</p>

                  <div className="mt-3 flex items-center justify-between text-xs pt-2 border-t border-gray-800/60">
                    <span className="font-mono text-gray-500 truncate max-w-[200px]">
                      {sc.principal}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleSimulate(sc);
                      }}
                      className="flex items-center gap-1 text-[11px] font-semibold text-sky-400 hover:text-sky-300 transition"
                    >
                      <Play className="w-3 h-3 fill-current" />
                      Run Test
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Event Details & Execution Console */}
            <div className="lg:col-span-7 space-y-6">
              {/* Active Scenario Card */}
              <div className="bg-gray-900/90 rounded-2xl border border-gray-800 p-6 shadow-xl">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-gray-800">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800/60">
                        {selectedScenario.mitre}
                      </span>
                      <span className="text-xs text-gray-400 font-mono">[{selectedScenario.tactic}]</span>
                    </div>
                    <h2 className="text-lg font-bold text-gray-100">{selectedScenario.title}</h2>
                  </div>

                  <button
                    onClick={() => handleSimulate(selectedScenario)}
                    disabled={isSimulating}
                    className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-sm bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white shadow-lg shadow-sky-500/25 transition active:scale-95 disabled:opacity-50"
                  >
                    {isSimulating ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Evaluating Rules...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-current" />
                        <span>Simulate Live Event</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Threat Detection & SOAR Outcome */}
                <div className="mt-5 space-y-4">
                  <div className="p-4 rounded-xl bg-gray-950/80 border border-gray-800/80">
                    <div className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-2">
                      Detection & Containment Pipeline
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-gray-500">Offending Actor:</span>
                        <p className="font-mono text-rose-400 font-medium truncate">{selectedScenario.principal}</p>
                      </div>
                      <div>
                        <span className="text-gray-500">Source IP Address:</span>
                        <p className="font-mono text-gray-200">{selectedScenario.callerIp}</p>
                      </div>
                      <div>
                        <span className="text-gray-500">API Method Invoked:</span>
                        <p className="font-mono text-indigo-400 truncate">{selectedScenario.method}</p>
                      </div>
                      <div>
                        <span className="text-gray-500">Automated SOAR Action:</span>
                        <p className="font-mono text-emerald-400 font-bold">{selectedScenario.action}</p>
                      </div>
                    </div>
                  </div>

                  {/* Raw Audit Log Payload */}
                  <div>
                    <div className="flex items-center justify-between text-xs text-gray-400 mb-2 font-mono">
                      <span>GCP Cloud Audit Log (protoPayload)</span>
                      <span className="text-sky-400">Format: JSON</span>
                    </div>
                    <pre className="p-4 rounded-xl bg-[#070A10] border border-gray-800 text-[11px] font-mono text-gray-300 overflow-x-auto max-h-56">
                      {JSON.stringify(selectedScenario.rawJson, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: GEMINI AI INCIDENT DOSSIER */}
        {activeTab === 'ai' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-gradient-to-br from-indigo-950/40 via-gray-900 to-[#111827] border border-indigo-800/50 shadow-xl">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-9 h-9 rounded-xl bg-indigo-600/30 border border-indigo-500/40 flex items-center justify-center text-indigo-400">
                  <Sparkles className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-lg text-white">Gemini 2.5 SecOps Incident Investigation Dossier</h3>
                  <p className="text-xs text-indigo-300">
                    Autonomous Context Enrichment via BigQuery SIEM & LLM Incident Synthesis
                  </p>
                </div>
              </div>

              <div className="mt-4 p-4 rounded-xl bg-gray-950/70 border border-indigo-900/40 flex flex-wrap items-center justify-between gap-4">
                <div className="text-xs font-mono">
                  <span className="text-gray-400">Active Incident: </span>
                  <span className="text-sky-400 font-bold">{selectedScenario.title}</span>
                  <span className="text-gray-500"> ({selectedScenario.mitre})</span>
                </div>
                <div className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4" />
                  <span>SOAR Action: {selectedScenario.action}</span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-6 rounded-2xl bg-gray-900 border border-gray-800 space-y-4">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-sky-400 mb-1 flex items-center gap-1.5">
                    <Shield className="w-4 h-4" />
                    1. Executive Incident Summary
                  </h4>
                  <p className="text-sm text-gray-300 leading-relaxed bg-gray-950/60 p-3 rounded-xl border border-gray-800/60">
                    {selectedScenario.aiReport.executive}
                  </p>
                </div>

                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-rose-400 mb-1 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    2. Threat Actor Profile & Attack Vector
                  </h4>
                  <p className="text-sm text-gray-300 leading-relaxed bg-gray-950/60 p-3 rounded-xl border border-gray-800/60">
                    {selectedScenario.aiReport.actor}
                  </p>
                </div>

                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 mb-1 flex items-center gap-1.5">
                    <Zap className="w-4 h-4" />
                    3. Blast Radius Assessment
                  </h4>
                  <p className="text-sm text-gray-300 leading-relaxed bg-gray-950/60 p-3 rounded-xl border border-gray-800/60">
                    {selectedScenario.aiReport.blastRadius}
                  </p>
                </div>
              </div>

              <div className="p-6 rounded-2xl bg-gray-900 border border-gray-800 space-y-4">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-1 flex items-center gap-1.5">
                    <CheckCircle className="w-4 h-4" />
                    4. Automated Containment Verification
                  </h4>
                  <p className="text-sm text-gray-300 leading-relaxed bg-gray-950/60 p-3 rounded-xl border border-gray-800/60">
                    {selectedScenario.aiReport.containment}
                  </p>
                </div>

                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-400 mb-2 flex items-center gap-1.5">
                    <Terminal className="w-4 h-4" />
                    5. Prioritized SOC Analyst Action Checklist
                  </h4>
                  <div className="space-y-2">
                    {selectedScenario.aiReport.checklist.map((item, idx) => (
                      <div
                        key={idx}
                        className="flex items-start gap-2.5 p-3 rounded-xl bg-gray-950/60 border border-gray-800/60 text-xs text-gray-200"
                      >
                        <span className="w-5 h-5 rounded-full bg-indigo-950 text-indigo-400 border border-indigo-800 flex items-center justify-center font-mono text-[10px] shrink-0 font-bold">
                          {idx + 1}
                        </span>
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: BIGQUERY SIEM ANALYTICS */}
        {activeTab === 'bigquery' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-6 rounded-2xl bg-gray-900 border border-gray-800">
                <div className="flex items-center gap-3 mb-4">
                  <Database className="w-5 h-5 text-sky-400" />
                  <h3 className="font-bold text-base text-white">BigQuery SIEM Dataset: secops_siem</h3>
                </div>
                <div className="space-y-3 text-xs">
                  <div className="p-3 rounded-xl bg-gray-950 border border-gray-800">
                    <span className="font-mono text-sky-400 font-bold block mb-1">secops_siem.audit_events</span>
                    <span className="text-gray-400">Partitioned: DAY (timestamp) | Clustered: principal_email, service_name, method_name, severity</span>
                  </div>
                  <div className="p-3 rounded-xl bg-gray-950 border border-gray-800">
                    <span className="font-mono text-emerald-400 font-bold block mb-1">secops_siem.security_alerts</span>
                    <span className="text-gray-400">Partitioned: DAY (timestamp) | Clustered: rule_id, severity, mitre_technique, status</span>
                  </div>
                </div>
              </div>

              <div className="p-6 rounded-2xl bg-gray-900 border border-gray-800">
                <div className="flex items-center gap-3 mb-4">
                  <ExternalLink className="w-5 h-5 text-indigo-400" />
                  <h3 className="font-bold text-base text-white">Direct GCP Console Links</h3>
                </div>
                <div className="space-y-2 text-xs">
                  <a
                    href="https://console.cloud.google.com/bigquery?project=financial-automation-data"
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between p-3 rounded-xl bg-gray-950 hover:bg-gray-800 transition border border-gray-800 text-sky-400"
                  >
                    <span>Open BigQuery SQL Workspace</span>
                    <ArrowUpRight className="w-4 h-4" />
                  </a>
                  <a
                    href="https://console.cloud.google.com/cloudpubsub/topic/list?project=financial-automation-data"
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between p-3 rounded-xl bg-gray-950 hover:bg-gray-800 transition border border-gray-800 text-emerald-400"
                  >
                    <span>Open Pub/Sub Topics & Subscriptions</span>
                    <ArrowUpRight className="w-4 h-4" />
                  </a>
                  <a
                    href="https://console.cloud.google.com/logs/sinks?project=financial-automation-data"
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between p-3 rounded-xl bg-gray-950 hover:bg-gray-800 transition border border-gray-800 text-indigo-400"
                  >
                    <span>Open Cloud Logging Audit Sinks</span>
                    <ArrowUpRight className="w-4 h-4" />
                  </a>
                </div>
              </div>
            </div>

            <div className="p-6 rounded-2xl bg-gray-900 border border-gray-800">
              <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-3">
                Live Threat Hunting SQL Query
              </h4>
              <pre className="p-4 rounded-xl bg-[#070A10] border border-gray-800 text-xs font-mono text-sky-300 overflow-x-auto">
{`-- Find all high-privilege IAM and Credential actions in the last 24 hours
SELECT 
  timestamp,
  principal_email,
  caller_ip,
  method_name,
  resource_name,
  severity
FROM \`financial-automation-data.secops_siem.audit_events\`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
  AND (
    method_name LIKE '%CreateServiceAccountKey%'
    OR method_name LIKE '%SetIamPolicy%'
    OR method_name LIKE '%setIamPermissions%'
  )
ORDER BY timestamp DESC
LIMIT 50;`}
              </pre>
            </div>
          </div>
        )}

        {/* TAB 4: ARCHITECTURE & GCP MAP */}
        {activeTab === 'architecture' && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-gray-900 border border-gray-800">
              <h3 className="font-bold text-lg text-white mb-2">33 Provisioned Google Cloud Resources</h3>
              <p className="text-xs text-gray-400 mb-6">
                All resources provisioned via declarative Terraform (IaC) in project <span className="text-sky-400 font-mono">financial-automation-data</span>.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-2">
                  <div className="text-sky-400 font-bold text-sm">1. Ingestion Layer</div>
                  <div className="text-gray-300">● sink-sentinel-audit-telemetry</div>
                  <div className="text-gray-300">● cloud-security-telemetry (Topic)</div>
                  <div className="text-gray-300">● sub-detector-telemetry</div>
                  <div className="text-gray-300">● security-telemetry-dlq</div>
                </div>

                <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-2">
                  <div className="text-emerald-400 font-bold text-sm">2. BigQuery SIEM</div>
                  <div className="text-gray-300">● secops_siem (Dataset)</div>
                  <div className="text-gray-300">● audit_events (Partitioned)</div>
                  <div className="text-gray-300">● security_alerts (Partitioned)</div>
                  <div className="text-gray-300">● security-alerts-critical (Topic)</div>
                </div>

                <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-2">
                  <div className="text-indigo-400 font-bold text-sm">3. Least-Privilege IAM</div>
                  <div className="text-gray-300">● sa-sentinel-detector</div>
                  <div className="text-gray-300">● sa-sentinel-remediator</div>
                  <div className="text-gray-300">● sa-sentinel-ai-analyst</div>
                  <div className="text-gray-300">● 10 Granular IAM Role Bindings</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800/80 bg-[#0B0F19] py-6 text-center text-xs text-gray-500">
        <p>
          CloudSecOps Sentinel • Engineered for Google Cloud Platform • Deployed at{' '}
          <span className="text-sky-400 font-mono">cloudops.cyberforage.space</span>
        </p>
      </footer>
    </div>
  );
}
