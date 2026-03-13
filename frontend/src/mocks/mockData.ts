// ==========================================================================
// IoT ThreatGraph Sentinel — Mock Data (Dummy / Development Only)
// Replace with live API data after P3 backend is integrated on Day 3.
// ==========================================================================

import type {
  Device,
  AlertEvent,
  GraphEnrichment,
  IncidentReport,
  AnomalyResult,
} from '../types/contracts';

// ── Mock Devices (GET /devices) ──────────────────────────────────────────
export const MOCK_DEVICES: Device[] = [
  {
    device_id: 'cam-001',
    device_type: 'camera',
    risk_score: 87,
    confidence: 'high',
    last_seen: '2026-03-13T11:00:00Z',
    status: 'critical',
  },
  {
    device_id: 'router-02',
    device_type: 'router',
    risk_score: 61,
    confidence: 'medium',
    last_seen: '2026-03-13T11:01:00Z',
    status: 'suspicious',
  },
  {
    device_id: 'nvr-01',
    device_type: 'nvr',
    risk_score: 54,
    confidence: 'medium',
    last_seen: '2026-03-13T11:01:30Z',
    status: 'suspicious',
  },
  {
    device_id: 'sensor-07',
    device_type: 'sensor',
    risk_score: 12,
    confidence: 'low',
    last_seen: '2026-03-13T10:58:00Z',
    status: 'normal',
  },
  {
    device_id: 'access-ctrl-01',
    device_type: 'access_control',
    risk_score: 34,
    confidence: 'low',
    last_seen: '2026-03-13T11:00:45Z',
    status: 'normal',
  },
  {
    device_id: 'thermostat-03',
    device_type: 'thermostat',
    risk_score: 8,
    confidence: 'low',
    last_seen: '2026-03-13T10:55:00Z',
    status: 'normal',
  },
];

// ── Mock Anomaly Result (P1 → P2/P3 contract) ────────────────────────────
export const MOCK_ANOMALY_RESULT: AnomalyResult = {
  timestamp: '2026-03-13T11:01:00Z',
  device_id: 'cam-001',
  device_type: 'camera',
  scores: {
    isolation_forest: 78.4,
    autoencoder: 64.2,
    final_risk: 73.1,
    confidence: 'high',
  },
  reason_codes: ['outbound_volume_spike', 'dest_ip_diversity_jump'],
  explanations: [
    'Outbound traffic is 6.8x above rolling baseline',
    'Unique destination IP count increased from 2 to 9',
  ],
};

// ── Mock Graph Enrichment (P2 → P3/P4 contract) ─────────────────────────
export const MOCK_GRAPH_ENRICHMENT: GraphEnrichment = {
  timestamp: '2026-03-13T11:01:05Z',
  source_device: 'cam-001',
  propagation_risk: 0.81,
  neighbors: ['router-02', 'nvr-01', 'sensor-07'],
  next_target_prediction: [
    { device_id: 'router-02', score: 0.88, why: 'high betweenness centrality' },
    { device_id: 'nvr-01', score: 0.79, why: 'frequent bidirectional flow' },
  ],
  attack_paths: [['cam-001', 'router-02', 'access-ctrl-01']],
  mitre: { tactic: 'Lateral Movement', technique: 'T1021' },
};

// ── Mock Alert Events (P3 → P4 via WebSocket) ────────────────────────────
export const MOCK_ALERTS: AlertEvent[] = [
  {
    event_type: 'alert.created',
    event_id: 'evt_4f20',
    timestamp: '2026-03-13T11:01:07Z',
    severity: 'high',
    device_id: 'cam-001',
    device_type: 'camera',
    risk_score: 87,
    confidence: 'high',
    reasons: [
      'Outbound traffic is 6.8x above rolling baseline',
      'Likely propagation path detected',
    ],
    mitre: { tactic: 'Lateral Movement', technique: 'T1021' },
    graph: {
      path: ['cam-001', 'router-02', 'access-ctrl-01'],
      next_targets: ['router-02', 'nvr-01'],
    },
  },
  {
    event_type: 'alert.created',
    event_id: 'evt_3a11',
    timestamp: '2026-03-13T11:00:30Z',
    severity: 'medium',
    device_id: 'router-02',
    device_type: 'router',
    risk_score: 61,
    confidence: 'medium',
    reasons: [
      'Unusual port-scan pattern observed',
      'Elevated UDP traffic to external IPs',
    ],
    mitre: { tactic: 'Discovery', technique: 'T1046' },
    graph: {
      path: ['router-02', 'access-ctrl-01'],
      next_targets: ['access-ctrl-01'],
    },
  },
  {
    event_type: 'alert.created',
    event_id: 'evt_2c09',
    timestamp: '2026-03-13T10:59:00Z',
    severity: 'medium',
    device_id: 'nvr-01',
    device_type: 'nvr',
    risk_score: 54,
    confidence: 'medium',
    reasons: ['Repeated connection attempts to external RTSP server'],
    mitre: { tactic: 'Exfiltration', technique: 'T1048' },
    graph: {
      path: ['nvr-01', 'router-02'],
      next_targets: ['router-02'],
    },
  },
];

// ── Mock Incident Report (P3 output) ─────────────────────────────────────
export const MOCK_INCIDENT_REPORT: IncidentReport = {
  report_id: 'rep_001',
  generated_at: '2026-03-13T11:02:00Z',
  incident_summary: 'Potential lateral movement initiated from cam-001',
  affected_devices: ['cam-001', 'router-02', 'access-ctrl-01'],
  evidence: {
    risk_score: 87,
    explanations: [
      'Outbound traffic spike',
      'Unusual destination fan-out',
    ],
    mitre: [{ tactic: 'Lateral Movement', technique: 'T1021' }],
  },
  recommendations: [
    'Isolate cam-001 into quarantine VLAN',
    'Block outbound connections to unseen external endpoints',
    'Run firmware integrity check on router-02',
  ],
};

// ── Per-device risk trend data for drill-down charts ────────────────────
// Each entry is a 10-minute window sampled at 2-minute intervals.
// Replace with live /devices/{id}/trend data when P3 wires it up.
export const MOCK_RISK_TRENDS: Record<string, { time: string; risk: number }[]> = {
  'cam-001': [
    { time: '10:50', risk: 12 },
    { time: '10:52', risk: 18 },
    { time: '10:54', risk: 25 },
    { time: '10:56', risk: 42 },
    { time: '10:58', risk: 63 },
    { time: '11:00', risk: 78 },
    { time: '11:01', risk: 87 },
  ],
  'router-02': [
    { time: '10:50', risk: 8 },
    { time: '10:52', risk: 14 },
    { time: '10:54', risk: 22 },
    { time: '10:56', risk: 35 },
    { time: '10:58', risk: 48 },
    { time: '11:00', risk: 56 },
    { time: '11:01', risk: 61 },
  ],
  'nvr-01': [
    { time: '10:50', risk: 10 },
    { time: '10:52', risk: 16 },
    { time: '10:54', risk: 28 },
    { time: '10:56', risk: 36 },
    { time: '10:58', risk: 44 },
    { time: '11:00', risk: 51 },
    { time: '11:01', risk: 54 },
  ],
  'sensor-07': [
    { time: '10:50', risk: 5 },
    { time: '10:52', risk: 7 },
    { time: '10:54', risk: 8 },
    { time: '10:56', risk: 10 },
    { time: '10:58', risk: 11 },
    { time: '11:00', risk: 12 },
    { time: '11:01', risk: 12 },
  ],
  'access-ctrl-01': [
    { time: '10:50', risk: 14 },
    { time: '10:52', risk: 18 },
    { time: '10:54', risk: 22 },
    { time: '10:56', risk: 26 },
    { time: '10:58', risk: 30 },
    { time: '11:00', risk: 33 },
    { time: '11:01', risk: 34 },
  ],
  'thermostat-03': [
    { time: '10:50', risk: 3 },
    { time: '10:52', risk: 4 },
    { time: '10:54', risk: 5 },
    { time: '10:56', risk: 6 },
    { time: '10:58', risk: 7 },
    { time: '11:00', risk: 8 },
    { time: '11:01', risk: 8 },
  ],
};

/** @deprecated Use MOCK_RISK_TRENDS['cam-001'] or look up by device_id. */
export const MOCK_RISK_TREND = MOCK_RISK_TRENDS['cam-001'];
