import { useEffect, useMemo, useState } from 'react';
import type { Device, GraphEnrichment, MitreTag } from '../types/contracts';

type ScenarioSeries = {
  id: string;
  name: string;
  description: string;
  devices: string[];
  path: string[];
  defaultRisk: number;
  defaultReasons: string[];
  fallbackMitre: MitreTag;
};

type SimulateThreatPanelProps = {
  open: boolean;
  devices: Device[];
  apiBaseUrl: string;
  onGraphInjected: (enrichment: GraphEnrichment) => void;
  onClose: () => void;
};

type ConnectionSet = 'fanout' | 'chain' | 'pivot';

const ALERT_THRESHOLD = 65;

const REASON_OPTIONS = [
  'outbound_volume_spike',
  'dest_ip_diversity_jump',
  'high_port_entropy',
  'high_packet_rate',
  'udp_dominance',
  'port_scan_detected',
] as const;

const REASON_EXPLANATIONS: Record<string, string> = {
  outbound_volume_spike: 'Outbound traffic is above rolling baseline and suggests exfiltration intent.',
  dest_ip_diversity_jump: 'Destination fan-out increased sharply, indicating lateral discovery behavior.',
  high_port_entropy: 'Destination port entropy is unusually high and consistent with probing.',
  high_packet_rate: 'Packet rate is significantly above baseline for this device profile.',
  udp_dominance: 'UDP traffic ratio is unusually high compared with expected traffic mix.',
  port_scan_detected: 'Sequential destination port attempts indicate an active scan pattern.',
};

const REASON_MITRE: Record<string, MitreTag> = {
  outbound_volume_spike: { tactic: 'Exfiltration', technique: 'T1048' },
  dest_ip_diversity_jump: { tactic: 'Lateral Movement', technique: 'T1021' },
  high_port_entropy: { tactic: 'Discovery', technique: 'T1046' },
  high_packet_rate: { tactic: 'Command and Control', technique: 'T1071' },
  udp_dominance: { tactic: 'Command and Control', technique: 'T1095' },
  port_scan_detected: { tactic: 'Discovery', technique: 'T1046' },
};

const SCENARIOS: ScenarioSeries[] = [
  {
    id: 'camera-lateral-3',
    name: 'Series A: Camera Pivot (3 devices)',
    description: 'Small blast-radius chain showing quick lateral movement from camera to access control.',
    devices: ['cam-001', 'cam-002', 'cam-003', 'router-01', 'door-ctrl-01'],
    path: ['cam-002', 'router-01', 'door-ctrl-01'],
    defaultRisk: 84,
    defaultReasons: ['dest_ip_diversity_jump', 'high_port_entropy'],
    fallbackMitre: { tactic: 'Lateral Movement', technique: 'T1021' },
  },
  {
    id: 'sensor-to-edge-4',
    name: 'Series B: Sensor Edge Expansion (4 devices)',
    description: 'Mid-size chain highlighting suspicious edge traffic through router to external target.',
    devices: ['sensor-01', 'sensor-02', 'sensor-03', 'router-02', 'nvr-01', 'internet-benign'],
    path: ['sensor-01', 'router-02', 'nvr-01', 'internet-benign'],
    defaultRisk: 71,
    defaultReasons: ['high_packet_rate', 'udp_dominance'],
    fallbackMitre: { tactic: 'Command and Control', technique: 'T1071' },
  },
  {
    id: 'nvr-storage-exfil-5',
    name: 'Series C: Storage Exfil Chain (5 devices)',
    description: 'Longer path showing surveillance backend compromise and exfiltration route.',
    devices: ['nvr-01', 'storage-01', 'router-01', 'door-ctrl-02', 'external-unknown'],
    path: ['nvr-01', 'storage-01', 'router-01', 'door-ctrl-02', 'external-unknown'],
    defaultRisk: 90,
    defaultReasons: ['outbound_volume_spike', 'high_packet_rate'],
    fallbackMitre: { tactic: 'Exfiltration', technique: 'T1048' },
  },
];

function clampRisk(value: number): number {
  return Math.max(0, Math.min(100, value));
}

function confidenceFromRisk(risk: number): 'low' | 'medium' | 'high' {
  if (risk >= 80) return 'high';
  if (risk >= 50) return 'medium';
  return 'low';
}

function severityFromRisk(risk: number): 'low' | 'medium' | 'high' | 'critical' {
  if (risk >= 85) return 'critical';
  if (risk >= 70) return 'high';
  if (risk >= 50) return 'medium';
  return 'low';
}

function mitreFromReasons(reasonCodes: string[], fallback: MitreTag): MitreTag {
  for (const code of reasonCodes) {
    const mapped = REASON_MITRE[code];
    if (mapped) return mapped;
  }
  return fallback;
}

export function SimulateThreatPanel({ open, devices, apiBaseUrl, onGraphInjected, onClose }: SimulateThreatPanelProps) {
  const [scenarioId, setScenarioId] = useState<string>(SCENARIOS[0].id);
  const [deviceId, setDeviceId] = useState<string>('');
  const [riskScore, setRiskScore] = useState<number>(SCENARIOS[0].defaultRisk);
  const [reasonCodes, setReasonCodes] = useState<string[]>(SCENARIOS[0].defaultReasons);
  const [submitting, setSubmitting] = useState(false);
  const [status, setStatus] = useState<string>('');
  const [connectionSet, setConnectionSet] = useState<ConnectionSet>('fanout');
  const [connectionsCount, setConnectionsCount] = useState<number>(6);

  const scenario = useMemo(
    () => SCENARIOS.find((s) => s.id === scenarioId) ?? SCENARIOS[0],
    [scenarioId],
  );

  const availableDeviceIds = useMemo(() => {
    return Array.from(new Set(devices.map((d) => d.device_id))).sort((a, b) => a.localeCompare(b));
  }, [devices]);

  useEffect(() => {
    if (!open) {
      return;
    }
    setRiskScore(scenario.defaultRisk);
    setReasonCodes(scenario.defaultReasons);
    setStatus('');
  }, [open, scenario.defaultReasons, scenario.defaultRisk]);

  useEffect(() => {
    if (!open) {
      return;
    }
    if (availableDeviceIds.length === 0) {
      setDeviceId('');
      return;
    }
    if (!availableDeviceIds.includes(deviceId)) {
      setDeviceId(availableDeviceIds[0]);
    }
  }, [availableDeviceIds, deviceId, open]);

  const selectedDevice = useMemo(
    () => devices.find((d) => d.device_id === deviceId) ?? null,
    [devices, deviceId],
  );

  const severityLabel = severityFromRisk(riskScore);

  const previewPath = useMemo(() => {
    const sourceId = deviceId || scenario.path[0] || scenario.devices[0] || 'device';
    const candidates = Array.from(new Set([
      ...scenario.devices,
      ...scenario.path,
      'router-01',
      'router-02',
      'storage-01',
      'nvr-01',
      'door-ctrl-01',
      'door-ctrl-02',
      'sensor-01',
      'sensor-02',
      'sensor-03',
      'external-unknown',
      'internet-benign',
    ])).filter((id) => id !== sourceId);

    const required = Math.max(1, Math.min(12, connectionsCount));
    const targets = candidates.slice(0, required);
    while (targets.length < required) {
      targets.push(`sim-node-${targets.length + 1}`);
    }

    if (connectionSet === 'chain') {
      return [sourceId, ...targets];
    }
    if (connectionSet === 'pivot') {
      const pivot = targets[0] ?? 'sim-pivot';
      const firstTarget = targets[1] ?? pivot;
      return [sourceId, pivot, firstTarget];
    }
    const firstTarget = targets[0] ?? 'sim-target';
    return [sourceId, firstTarget];
  }, [scenario, connectionsCount, connectionSet, deviceId]);

  const toggleReason = (code: string) => {
    setReasonCodes((prev) => {
      if (prev.includes(code)) {
        return prev.filter((x) => x !== code);
      }
      return [...prev, code];
    });
  };

  const handleFireThreat = async () => {
    if (!selectedDevice) {
      setStatus('No live device is available for this scenario.');
      return;
    }

    const finalRisk = clampRisk(riskScore);
    const timestamp = new Date().toISOString();
    const selectedReasons = reasonCodes.length > 0 ? reasonCodes : scenario.defaultReasons;
    const explanations = selectedReasons.map((code) => REASON_EXPLANATIONS[code] ?? `Anomaly marker: ${code}`);
    const mitre = mitreFromReasons(selectedReasons, scenario.fallbackMitre);

    const baseCandidates = Array.from(new Set([
      ...scenario.devices,
      ...scenario.path,
      'router-01',
      'router-02',
      'storage-01',
      'nvr-01',
      'door-ctrl-01',
      'door-ctrl-02',
      'sensor-01',
      'sensor-02',
      'sensor-03',
      'external-unknown',
      'internet-benign',
    ])).filter((id) => id !== selectedDevice.device_id);

    const required = Math.max(1, Math.min(12, connectionsCount));
    const targets: string[] = baseCandidates.slice(0, required);
    while (targets.length < required) {
      targets.push(`sim-node-${targets.length + 1}`);
    }

    let neighbors = targets;
    let attackPaths: string[][] = [];

    if (connectionSet === 'chain') {
      attackPaths = [[selectedDevice.device_id, ...targets]];
    } else if (connectionSet === 'pivot') {
      const pivot = targets[0];
      attackPaths = targets.slice(1).map((t) => [selectedDevice.device_id, pivot, t]);
      if (attackPaths.length === 0) {
        attackPaths = [[selectedDevice.device_id, pivot]];
      }
      neighbors = Array.from(new Set([pivot, ...targets.slice(1)]));
    } else {
      // fanout
      attackPaths = targets.map((t) => [selectedDevice.device_id, t]);
    }

    const enrichment: GraphEnrichment = {
      timestamp,
      source_device: selectedDevice.device_id,
      propagation_risk: Number((Math.min(1, Math.max(0.1, finalRisk / 100) * (0.55 + required * 0.03))).toFixed(3)),
      neighbors,
      next_target_prediction: neighbors.slice(0, 5).map((neighborId, idx) => ({
        device_id: neighborId,
        score: Number((0.92 - idx * 0.12).toFixed(3)),
        why: `${connectionSet} connection set`,
      })),
      attack_paths: attackPaths,
      mitre,
    };

    const anomalyPayload = {
      timestamp,
      device_id: selectedDevice.device_id,
      device_type: selectedDevice.device_type,
      scores: {
        isolation_forest: Number((finalRisk * 0.94).toFixed(3)),
        autoencoder: Number((Math.min(100, finalRisk * 1.03)).toFixed(3)),
        final_risk: finalRisk,
        confidence: confidenceFromRisk(finalRisk),
      },
      // source:simulator tag makes the feed show ⚡ manual badge
      reason_codes: ['source:simulator', ...selectedReasons],
      explanations,
    };

    setSubmitting(true);
    setStatus('Submitting simulated threat...');

    try {
      const graphRes = await fetch(`${apiBaseUrl}/ingest/graph`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(enrichment),
      });
      if (!graphRes.ok) {
        throw new Error('Graph enrichment submission failed.');
      }
      onGraphInjected(enrichment);

      const anomalyRes = await fetch(`${apiBaseUrl}/ingest/anomaly`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(anomalyPayload),
      });
      if (!anomalyRes.ok) {
        throw new Error('Anomaly submission failed.');
      }

      if (finalRisk < ALERT_THRESHOLD) {
        setStatus(
          `Graph updated for ${selectedDevice.device_id} with ${required} connections (${connectionSet}). Risk ${finalRisk.toFixed(1)} is below alert threshold ${ALERT_THRESHOLD}, so alert feed/WS may stay unchanged.`,
        );
      } else {
        setStatus(
          `Threat injected for ${selectedDevice.device_id} (${scenario.name}) with ${required} connections (${connectionSet}). Risk ${finalRisk.toFixed(1)} / ${severityLabel}.`,
        );
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      setStatus(`Simulation failed: ${message}`);
    } finally {
      setSubmitting(false);
    }
  };

  if (!open) {
    return null;
  }

  return (
    <aside className="sim-panel" role="dialog" aria-label="Simulate Threat Panel">
      <div className="sim-panel-header">
        <strong>Simulate Threat</strong>
        <button className="btn btn-ghost" onClick={onClose}>Close</button>
      </div>

      <div className="sim-panel-body">
        <label className="sim-label" htmlFor="sim-series">Scenario Series</label>
        <select
          id="sim-series"
          className="sim-control"
          value={scenarioId}
          onChange={(e) => setScenarioId(e.target.value)}
        >
          {SCENARIOS.map((s) => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>
        <div className="sim-help">{scenario.description}</div>

        <label className="sim-label" htmlFor="sim-device">Device</label>
        <select
          id="sim-device"
          className="sim-control"
          value={deviceId}
          onChange={(e) => setDeviceId(e.target.value)}
          disabled={availableDeviceIds.length === 0}
        >
          {availableDeviceIds.map((id) => (
            <option key={id} value={id}>{id}</option>
          ))}
        </select>

        <label className="sim-label" htmlFor="sim-risk">Risk Score ({riskScore.toFixed(0)})</label>
        <input
          id="sim-risk"
          type="range"
          min={0}
          max={100}
          value={riskScore}
          onChange={(e) => setRiskScore(Number(e.target.value))}
        />
        <div className="sim-help">Severity: <span className={`badge badge-${severityLabel}`}>{severityLabel}</span></div>

        <label className="sim-label" htmlFor="sim-connection-set">Connection Set</label>
        <select
          id="sim-connection-set"
          className="sim-control"
          value={connectionSet}
          onChange={(e) => setConnectionSet(e.target.value as ConnectionSet)}
        >
          <option value="fanout">Fanout (1 source to many targets)</option>
          <option value="chain">Chain (linear spread path)</option>
          <option value="pivot">Pivot (source to pivot to targets)</option>
        </select>

        <label className="sim-label" htmlFor="sim-connections">Connections ({connectionsCount})</label>
        <input
          id="sim-connections"
          type="range"
          min={1}
          max={12}
          value={connectionsCount}
          onChange={(e) => setConnectionsCount(Number(e.target.value))}
        />
        <div className="sim-help">Generate up to 12 simulated connections per run.</div>

        <div className="sim-label">Reason Codes</div>
        <div className="sim-reasons">
          {REASON_OPTIONS.map((code) => (
            <label key={code} className="sim-checkbox-row">
              <input
                type="checkbox"
                checked={reasonCodes.includes(code)}
                onChange={() => toggleReason(code)}
              />
              <span className="mono">{code}</span>
            </label>
          ))}
        </div>

        <button className="btn btn-primary" onClick={handleFireThreat} disabled={submitting || !selectedDevice}>
          {submitting ? 'Firing...' : 'Fire Anomaly'}
        </button>

        <div className="sim-help">
          Series preview: <span className="mono">{previewPath.join(' -> ')}</span>
        </div>
        {status && <div className="sim-status">{status}</div>}
      </div>
    </aside>
  );
}
