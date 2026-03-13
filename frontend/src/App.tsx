import { useEffect, useRef, useState, useCallback } from 'react';
import './index.css';

import { DeviceList } from './components/DeviceList';
import { ThreatGraph } from './components/ThreatGraph';
import { AlertFeed } from './components/AlertFeed';
import { IncidentPanel } from './components/IncidentPanel';
import { ReplayTimeline } from './components/ReplayTimeline';
import { buildReplayFrames } from './components/replayUtils';

import { MockWebSocket } from './mocks/mockWebSocket';
import {
  MOCK_DEVICES,
  MOCK_ALERTS,
  MOCK_GRAPH_ENRICHMENT,
} from './mocks/mockData';

import type { AlertEvent, Device } from './types/contracts';
import { Activity, Wifi } from 'lucide-react';

// ── App ────────────────────────────────────────────────────────────────────
export default function App() {
  // State
  const [alerts, setAlerts] = useState<AlertEvent[]>(MOCK_ALERTS);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [latestAlert, setLatestAlert] = useState<AlertEvent | null>(MOCK_ALERTS[0] ?? null);
  const [replayIndex, setReplayIndex] = useState(0);
  const wsStatus: 'live' | 'mock' = 'mock';

  // Build replay frames from alerts
  const replayFrames = buildReplayFrames(alerts);

  // Mock WebSocket
  const wsRef = useRef<MockWebSocket | null>(null);

  useEffect(() => {
    const ws = new MockWebSocket();
    wsRef.current = ws;

    ws.onAlert((evt) => {
      setAlerts((prev) => {
        // Avoid duplicate event IDs
        if (prev.some((a) => a.event_id === evt.event_id && a.timestamp === evt.timestamp)) {
          // Create a unique copy by bumping timestamp slightly
          const next: AlertEvent = {
            ...evt,
            event_id: `${evt.event_id}_${Date.now()}`,
            timestamp: new Date().toISOString(),
          };
          return [next, ...prev].slice(0, 50);
        }
        setLatestAlert(evt);
        return [evt, ...prev].slice(0, 50);
      });
    });

    ws.connect(5000); // new alert every 5 seconds
    return () => ws.disconnect();
  }, []);

  // Node click from graph → open IncidentPanel
  const handleNodeClick = useCallback((deviceId: string) => {
    const device = MOCK_DEVICES.find((d) => d.device_id === deviceId) ?? null;
    setSelectedDevice(device);
    const deviceAlert = alerts.find((a) => a.device_id === deviceId) ?? null;
    if (deviceAlert) setLatestAlert(deviceAlert);
  }, [alerts]);

  // Alert click → open IncidentPanel for that device
  const handleAlertClick = useCallback((alert: AlertEvent) => {
    const device = MOCK_DEVICES.find((d) => d.device_id === alert.device_id) ?? null;
    setSelectedDevice(device);
    setLatestAlert(alert);
  }, []);

  // Device click from list → open IncidentPanel
  const handleDeviceSelect = useCallback((device: Device) => {
    setSelectedDevice(device);
    const deviceAlert = alerts.find((a) => a.device_id === device.device_id) ?? null;
    if (deviceAlert) setLatestAlert(deviceAlert);
  }, [alerts]);

  // Replay-index change → highlight the alert at that frame
  const handleReplayChange = useCallback((index: number) => {
    setReplayIndex(index);
    const frame = replayFrames[index];
    if (!frame) return;
    const correspondingAlert = alerts.find((a) => a.device_id === frame.label) ?? null;
    if (correspondingAlert) {
      setLatestAlert(correspondingAlert);
      const device = MOCK_DEVICES.find((d) => d.device_id === frame.label) ?? null;
      setSelectedDevice(device);
    }
  }, [replayFrames, alerts]);

  // Determine graph enrichment for current replay frame
  const activeEnrichment = MOCK_GRAPH_ENRICHMENT;

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
            <Wifi size={12} style={{ color: 'var(--risk-low)' }} />
            <span style={{ color: 'var(--risk-low)' }}>{wsStatus === 'mock' ? 'Mock WS' : 'Live WS'}</span>
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
            devices={MOCK_DEVICES}
            selectedId={selectedDevice?.device_id ?? null}
            onSelect={handleDeviceSelect}
          />

          {/* Center: Threat Graph */}
          <ThreatGraph
            devices={MOCK_DEVICES}
            enrichment={activeEnrichment}
            onNodeClick={handleNodeClick}
          />

          {/* Right: Incident Panel (drill-down) or Alert Feed toggle */}
          {selectedDevice ? (
            <IncidentPanel
              device={selectedDevice}
              latestAlert={latestAlert}
              onClose={() => setSelectedDevice(null)}
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
