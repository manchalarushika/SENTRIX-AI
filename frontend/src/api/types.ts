export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Asset {
  id: number;
  hostname: string;
  ip_address: string | null;
  operating_system: string;
  asset_type: string;
  department: string;
  criticality: string;
  network_zone: string;
  owner: string;
  status: string;
  internet_facing: boolean;
  business_value_per_hour: number;
  software: string[];
  connects_to: string[];
  risk_score: number;
  last_seen: string | null;
  created_at: string;
}

export interface SecurityEvent {
  id: number;
  timestamp: string;
  received_at: string;
  source: string;
  source_format: string;
  event_type: string;
  category: string;
  severity: Severity;
  hostname: string | null;
  user: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  process: string | null;
  command_line: string | null;
  description: string;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  classification: {
    rule_ids: string[];
    technique_name: string | null;
    base_score: number;
    indicators: { rule: string; name: string; technique: string; evidence: string; score: number }[];
    recommendation: string;
  } | null;
  anomaly_score: number;
  anomaly_details: {
    score: number;
    indicators: { indicator: string; contribution: number; detail: string }[];
    baseline: Record<string, unknown>;
  } | null;
  threat_score: number;
  incident_id: number | null;
  asset_id: number | null;
}

export interface Incident {
  id: number;
  ref: string;
  title: string;
  status: string;
  severity: Severity;
  category: string;
  risk_score: number;
  confidence: number;
  primary_hostname: string | null;
  hostnames: string[];
  users: string[];
  tactics: string[];
  techniques: string[];
  event_count: number;
  first_seen: string;
  last_seen: string;
  assignee: string | null;
  summary: string;
  analysis_version: number;
  analyzed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentResult {
  agent: string;
  role: string;
  method: string;
  confidence: number;
  summary: string;
  findings: Record<string, any>;
  votes: Record<string, { score: number; reason: string }> | null;
}

export interface CouncilVote {
  agent: string;
  weight: number;
  confidence: number;
  effective_weight: number;
  preferred: string;
  preferred_name: string;
  scores: Record<string, number>;
  reason: string;
}

export interface Council {
  method: string;
  decision: string;
  decision_name: string;
  consensus_score: number;
  agreement: number;
  first_choice_share: number;
  strength: string;
  margin: number;
  human_review_recommended: boolean;
  ranking: { playbook: string; name: string; score: number }[];
  votes: CouncilVote[];
  dissent: { agent: string; preferred: string; preferred_name: string; reason: string }[];
  ablation: { without: string; decision: string; decision_name: string; pivotal: boolean }[];
  weights: Record<string, number>;
  rationale: string;
  decision_id?: number;
}

export interface Analysis {
  version: number;
  analyzed_at: string;
  agents: Record<string, AgentResult>;
  pipeline: { agent: string; status: string; duration_ms: number; method: string }[];
  candidates: { id: string; name: string }[];
  council: Council;
  xai: {
    method: string;
    narrative: string[];
    evidence: {
      event_id: number;
      timestamp: string;
      event_type: string;
      hostname: string | null;
      threat_score: number;
      rule_evidence: { rule: string; name: string; technique: string; evidence: string }[];
      behaviour_evidence: { indicator: string; contribution: number; detail: string }[];
    }[];
    factor_attribution: { factor: string; share: number }[];
    decision_attribution: {
      agent: string;
      effective_weight: number;
      score_for_decision: number;
      score_for_runner_up: number;
      contribution_to_margin: number;
      reason: string;
    }[];
    counterfactuals: { without: string; decision_name: string; pivotal: boolean }[];
  };
  llm: {
    status: string;
    reason?: string;
    provider?: string;
    model?: string;
    latency_ms?: number;
    label?: string;
    content?: {
      executive_summary: string;
      attack_narrative: string;
      attacker_objective: string;
      recommended_next_steps: string[];
      open_questions: string[];
    };
  };
  verdict: string | null;
  proposed_action_ids: number[];
}

export interface IncidentDetail extends Incident {
  analysis: Analysis | null;
  notes: { id: number; author: string; body: string; created_at: string }[];
}

export interface ResponseAction {
  id: number;
  incident_id: number;
  decision_id: number | null;
  playbook: string;
  action_type: string;
  target: string;
  description: string;
  risk_level: string;
  requires_approval: boolean;
  status: string;
  requested_by: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_note: string | null;
  dispatch_result: Record<string, any> | null;
  created_at: string;
}

export interface CouncilDecision {
  id: number;
  incident_id: number;
  analysis_version: number;
  decided_playbook: string;
  decided_playbook_name: string;
  consensus_score: number;
  agreement: number;
  ranking: { playbook: string; name: string; score: number }[];
  votes: CouncilVote[];
  weights: Record<string, number>;
  dissent: { agent: string; preferred_name: string; reason: string }[];
  rationale: string;
  created_at: string;
}

export interface AgentRun {
  id: number;
  incident_id: number | null;
  analysis_version: number;
  agent: string;
  role: string;
  method: string;
  status: string;
  confidence: number;
  summary: string;
  output: Record<string, any> | null;
  error: string | null;
  duration_ms: number;
  started_at: string;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  actor: string;
  ip: string | null;
  action: string;
  entity_type: string;
  entity_id: string | null;
  outcome: string;
  details: Record<string, any> | null;
}

export interface GraphNode {
  id: string;
  label: string;
  zone: string;
  criticality: string;
  asset_type: string;
  vulns: string[];
  compromised: boolean;
  internet_facing?: boolean;
  risk_score?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  probability: number;
  on_attack_path: boolean;
}

export interface AttackPath {
  target: string;
  target_criticality: string;
  path: string[];
  hops: number;
  probability: number;
  priority: number;
}

export interface TwinResult {
  playbook: string;
  name: string;
  expected_compromised: number;
  p90_compromised: number;
  critical_asset_compromise_probability: number;
  expected_breach_loss: number;
  p90_breach_loss: number;
  response_disruption_cost: number;
  disrupted_assets: string[];
  expected_total_cost: number;
  cost_avoided_vs_monitoring: number;
  most_at_risk: { hostname: string; probability: number }[];
}

export interface TwinSimulation {
  status: string;
  reason?: string;
  method?: string;
  runs?: number;
  steps?: number;
  seed?: number;
  entry_points?: string[];
  results: TwinResult[];
  best_playbook?: string;
}

export interface IntelDoc {
  id?: number;
  doc_id: string;
  doc_type: string;
  title: string;
  body: string;
  tags: string[];
  source: string;
  url: string | null;
  score?: number;
}
