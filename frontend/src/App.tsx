import { useState, useCallback } from 'react';
import './index.css';

import { DeviceList } from './components/DeviceList';
import { ThreatGraph } from './components/ThreatGraph';
import { AlertFeed } from './components/AlertFeed';
import { IncidentPanel } from './components/IncidentPanel';
import { ReplayTimeline } from './components/ReplayTimeline';
import { buildReplayFrames } from './components/replayUtils';

import { useAlertStream } from './hooks/useAlertStream';
import { MOCK_DEVICES, MOCK_GRAPH_ENRICHMENT, MOCK_RISK_TRENDS } from './mocks/mockData';

import type { AlertEvent, Device, GraphEnrichment } from './types/contracts';
import { Activity, Wifi, WifiOff } from 'lucide-react';

// ── Derive graph enrichment from a live alert's graph payload ─────────────
function enrichmentFromAlert(alert: AlertEvent, fallback: GraphEnrichment): GraphEnrichment {
  if (!alert.graph?.path?.length) return fallback;
  return {
    ...fallback,
    timestamp: alert.timestamp,
    source_device: alert.device_id,
    attack_paths: [alert.graph.path],
    next_target_prediction: alert.graph.next_targets.map((id) => ({
      device_id: id,
      score: 0.75,
      why: 'propagation path detected',
    })),
    mitre: alert.mitre,
  };
}

// ── App ────────────────────────────────────────────────────────────────────
export default function App() {
  const { alerts, wsStatus } = useAlertStream();

  const devices = alerts.reduce<Device[]>((acc, alert) => {
    const existing = acc.find((d) => d.device_id === alert.device_id);
    if (existing) {
      if (alert.risk_score > existing.risk_score) {
        existing.risk_score = alert.risk_score;
        existing.confidence = alert.confidence;
      }
      existing.last_seen = alert.timestamp;
      existing.status = alert.risk_score >= 80
        ? 'critical'
        : alert.risk_score >= 40
          ? 'suspicious'
          : 'normal';
      return acc;
    }

    const knownDevice = MOCK_DEVICES.find((d) => d.device_id === alert.device_id);
    acc.push(knownDevice ?? {
      device_id: alert.device_id,
      device_type: alert.device_type,
      risk_score: alert.risk_score,
      confidence: alert.confidence,
      last_seen: alert.timestamp,
      status: alert.risk_score >= 80
        ? 'critical'
        : alert.risk_score >= 40
          ? 'suspicious'
          : 'normal',
    });
    return acc;
  }, [...MOCK_DEVICES]);

  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [latestAlert, setLatestAlert] = useState<AlertEvent | null>(alerts[0] ?? null);
  const [replayIndex, setReplayIndex] = useState(0);
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);

  // Build replay frames from alerts (sorted by timestamp asc)
  const replayFrames = buildReplayFrames(alerts);

  // Derive enrichment from latest alert's graph data (fallback to mock)
  const activeEnrichment = latestAlert
    ? enrichmentFromAlert(latestAlert, MOCK_GRAPH_ENRICHMENT)
    : MOCK_GRAPH_ENRICHMENT;

  // Per-device risk trend (falls back to cam-001 data if unknown device)
  const deviceTrend = selectedDevice
    ? (MOCK_RISK_TRENDS[selectedDevice.device_id] ?? MOCK_RISK_TRENDS['cam-001'])
    : undefined;

  // Node click from graph → open IncidentPanel
  const handleNodeClick = useCallback((deviceId: string) => {
    const device = devices.find((d) => d.device_id === deviceId) ?? null;
    setSelectedDevice(device);
    const deviceAlert = alerts.find((a) => a.device_id === deviceId) ?? null;
    if (deviceAlert) setLatestAlert(deviceAlert);
    setActiveNodeId(deviceId);
  }, [alerts, devices]);

  // Alert click → open IncidentPanel for that device
  const handleAlertClick = useCallback((alert: AlertEvent) => {
    const device = devices.find((d) => d.device_id === alert.device_id) ?? null;
    setSelectedDevice(device);
    setLatestAlert(alert);
    setActiveNodeId(alert.device_id);
  }, [devices]);

  // Device click from list → open IncidentPanel
  const handleDeviceSelect = useCallback((device: Device) => {
    setSelectedDevice(device);
    const deviceAlert = alerts.find((a) => a.device_id === device.device_id) ?? null;
    if (deviceAlert) setLatestAlert(deviceAlert);
    setActiveNodeId(device.device_id);
  }, [alerts]);

  // Replay-index change → highlight the alert at that frame
  const handleReplayChange = useCallback((index: number) => {
    setReplayIndex(index);
    const frame = replayFrames[index];
    if (!frame) return;
    setActiveNodeId(frame.label);
    const correspondingAlert = alerts.find((a) => a.device_id === frame.label) ?? null;
    if (correspondingAlert) {
      setLatestAlert(correspondingAlert);
      const device = MOCK_DEVICES.find((d) => d.device_id === frame.label) ?? null;
      setSelectedDevice(device);
    }
  }, [replayFrames, alerts]);

  // ── WS status indicator ──────────────────────────────────────────────────
  const wsColor =
    wsStatus === 'live' ? 'var(--risk-low)'
    : wsStatus === 'mock' ? 'var(--risk-medium)'
    : 'var(--risk-critical)';

  const wsLabel =
    wsStatus === 'live' ? 'Live WS'
    : wsStatus === 'connecting' ? 'Connecting…'
    : wsStatus === 'error' ? 'WS Error'
    : 'Mock WS';

  return (
    <div className="app-shell">
      {/* ── Top bar ─────────────────────────────────────────────────── */}
      <header className="top-bar">
        <div className="top-bar-logo">
          <span className="logo-dot" />
          <span className="gradient-text">IoT ThreatGraph Sentinel</span>
        </div>

        <div className="top-bar-meta">
          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <Activity size={12} />
            {alerts.length} alerts
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            {wsStatus === 'live'
              ? <Wifi size={12} style={{ color: wsColor }} />
              : <WifiOff size={12} style={{ color: wsColor }} />}
            <span style={{ color: wsColor }}>{wsLabel}</span>
          </span>
          <span className="mono" style={{ fontSize: 11 }}>
            {new Date().toLocaleTimeString()}
          </span>
        </div>
      </header>

      {/* ── Three-panel main content ─────────────────────────────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', flex: 1 }}>
        <div className="main-content" style={{ flex: 1 }}>
          {/* Left: Device List */}
          <DeviceList
            devices={devices}
            selectedId={selectedDevice?.device_id ?? null}
            onSelect={handleDeviceSelect}
          />

          {/* Center: Threat Graph */}
          <ThreatGraph
            devices={devices}
            enrichment={activeEnrichment}
            onNodeClick={handleNodeClick}
            activeNodeId={activeNodeId}
          />

          {/* Right: Incident Panel (drill-down) or Alert Feed */}
          {selectedDevice ? (
            <IncidentPanel
              device={selectedDevice}
              latestAlert={latestAlert}
              riskTrend={deviceTrend}
              onClose={() => { setSelectedDevice(null); setActiveNodeId(null); }}
            />
          ) : (
            <AlertFeed
              alerts={alerts}
              onAlertClick={handleAlertClick}
            />
          )}
        </div>

        {/* ── Bottom: Replay Timeline ───────────────────────────────── */}
        <ReplayTimeline
          frames={replayFrames}
          currentIndex={replayIndex}
          onChange={handleReplayChange}
        />
      </div>
    </div>
  );
}
