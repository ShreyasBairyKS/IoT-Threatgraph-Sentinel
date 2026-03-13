// ==========================================================================
// IoT ThreatGraph Sentinel — Frozen Data Contracts (Day 1)
// P4 TypeScript representations of Section 4 schemas.
// DO NOT MODIFY without all-4-member approval.
// ==========================================================================

// ── 4.1 Feature Window (P1 → P2/P3) ──────────────────────────────────────
export interface Features {
  flow_duration_mean: number;
  packet_rate: number;
  byte_volume: number;
  port_entropy: number;
  unique_dest_ips: number;
  tcp_ratio: number;
  udp_ratio: number;
  iat_mean: number;
  iat_std: number;
}

export interface FeatureWindow {
  window_start: string;
  window_end: string;
  device_id: string;
  features: Features;
}

// ── 4.2 Anomaly Result (P1 → P2/P3) ─────────────────────────────────────
export type ConfidenceLevel = 'low' | 'medium' | 'high';

export interface AnomalyScores {
  isolation_forest: number;
  autoencoder: number;
  final_risk: number;
  confidence: ConfidenceLevel;
}

export interface AnomalyResult {
  timestamp: string;
  device_id: string;
  device_type: string;
  scores: AnomalyScores;
  reason_codes: string[];
  explanations: string[];
}

// ── 4.3 Graph Enrichment (P2 → P3/P4) ────────────────────────────────────
export interface NextTargetPrediction {
  device_id: string;
  score: number;
  why: string;
}

export interface MitreTag {
  tactic: string;
  technique: string;
}

export interface GraphEnrichment {
  timestamp: string;
  source_device: string;
  propagation_risk: number;           // 0.0 – 1.0
  neighbors: string[];
  next_target_prediction: NextTargetPrediction[];
  attack_paths: string[][];
  mitre: MitreTag;
}

// ── 4.4 Alert Event (P3 → P4 via WebSocket) ─────────────────────────────
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface AlertGraph {
  path: string[];
  next_targets: string[];
}

export interface AlertEvent {
  event_type: 'alert.created';
  event_id: string;
  timestamp: string;
  severity: Severity;
  device_id: string;
  device_type: string;
  risk_score: number;                 // 0 – 100
  confidence: ConfidenceLevel;
  reasons: string[];
  mitre: MitreTag;
  graph: AlertGraph;
}

// ── 4.5 Incident Report (P3 output) ─────────────────────────────────────
export interface ReportEvidence {
  risk_score: number;
  explanations: string[];
  mitre: MitreTag[];
}

export interface IncidentReport {
  report_id: string;
  generated_at: string;
  incident_summary: string;
  affected_devices: string[];
  evidence: ReportEvidence;
  recommendations: string[];
}

// ── Device list item (derived from /devices endpoint) ───────────────────
export interface Device {
  device_id: string;
  device_type: string;
  risk_score: number;
  confidence: ConfidenceLevel;
  last_seen: string;
  status: 'normal' | 'suspicious' | 'critical';
}
