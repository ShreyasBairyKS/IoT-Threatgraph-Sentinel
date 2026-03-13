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
import type { GraphEnrichment } from './types/contracts';
import { Activity, Wifi } from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';
const WS_URL = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000/ws/alerts';
const MOCKS_ENABLED = import.meta.env.VITE_ENABLE_MOCK_FALLBACK === 'true';

// ── App ────────────────────────────────────────────────────────────────────
export default function App() {
  // State
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [graphEnrichment, setGraphEnrichment] = useState<GraphEnrichment | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [latestAlert, setLatestAlert] = useState<AlertEvent | null>(null);
  const [replayIndex, setReplayIndex] = useState(0);
  const [wsStatus, setWsStatus] = useState<'live' | 'mock' | 'offline'>('offline');

  // Build replay frames from alerts
  const replayFrames = buildReplayFrames(alerts);

  // Keep refs to avoid stale closures in WS listeners.
  const devicesRef = useRef<Device[]>([]);
  useEffect(() => {
    devicesRef.current = devices;
  }, [devices]);

  const fetchInitialData = useCallback(async () => {
    try {
      const [devicesRes, alertsRes, graphRes] = await Promise.all([
        fetch(`${API_BASE_URL}/devices`),
        fetch(`${API_BASE_URL}/alerts`),
        fetch(`${API_BASE_URL}/graph`),
      ]);

      if (!devicesRes.ok || !alertsRes.ok || !graphRes.ok) {
        throw new Error('One or more backend endpoints returned a non-200 response.');
      }

      const [liveDevices, liveAlerts, liveGraph] = await Promise.all([
        devicesRes.json() as Promise<Device[]>,
        alertsRes.json() as Promise<AlertEvent[]>,
        graphRes.json() as Promise<GraphEnrichment>,
      ]);

      setDevices(liveDevices);
      setAlerts(liveAlerts);
      setGraphEnrichment(liveGraph ?? null);
      setLatestAlert(liveAlerts[0] ?? null);
    } catch {
      if (MOCKS_ENABLED) {
        setDevices(MOCK_DEVICES);
        setAlerts(MOCK_ALERTS);
        setGraphEnrichment(MOCK_GRAPH_ENRICHMENT);
        setLatestAlert(MOCK_ALERTS[0] ?? null);
        setWsStatus('mock');
      } else {
        setDevices([]);
        setAlerts([]);
        setGraphEnrichment(null);
        setLatestAlert(null);
        setWsStatus('offline');
      }
    }
  }, []);

  // WebSocket reference (real or mock fallback)
  const wsRef = useRef<MockWebSocket | null>(null);
  const liveWsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let fallbackWs: MockWebSocket | null = null;

    const applyIncomingAlert = (evt: AlertEvent) => {
      setAlerts((prev) => {
        if (prev.some((a) => a.event_id === evt.event_id && a.timestamp === evt.timestamp)) {
          return prev;
        }
        return [evt, ...prev].slice(0, 50);
      });
      setLatestAlert(evt);

      setDevices((prev) => {
        const idx = prev.findIndex((d) => d.device_id === evt.device_id);
        if (idx === -1) {
          return prev;
        }
        const next = [...prev];
        next[idx] = {
          ...next[idx],
          risk_score: evt.risk_score,
          confidence: evt.confidence,
          last_seen: evt.timestamp,
          status:
            evt.severity === 'critical' ? 'critical' : evt.severity === 'high' ? 'suspicious' : 'normal',
        };
        return next;
      });
    };

    const startMockFallback = () => {
      if (!MOCKS_ENABLED) {
        setWsStatus('offline');
        return;
      }
      setWsStatus('mock');
      fallbackWs = new MockWebSocket();
      wsRef.current = fallbackWs;
      fallbackWs.onAlert(applyIncomingAlert);
      fallbackWs.connect(5000);
    };

    fetchInitialData();

    try {
      const liveWs = new WebSocket(WS_URL);
      liveWsRef.current = liveWs;

      liveWs.onopen = () => {
        setWsStatus('live');
      };

      liveWs.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data) as AlertEvent;
          if (parsed.event_type === 'alert.created') {
            applyIncomingAlert(parsed);
          }
        } catch {
          // Ignore malformed event payloads.
        }
      };

      liveWs.onerror = () => {
        if (wsRef.current == null) {
          startMockFallback();
        }
      };

      liveWs.onclose = () => {
        if (wsRef.current == null) {
          startMockFallback();
        }
      };
    } catch {
      startMockFallback();
    }

    return () => {
      if (liveWsRef.current) {
        liveWsRef.current.close();
        liveWsRef.current = null;
      }
      if (fallbackWs) {
        fallbackWs.disconnect();
        wsRef.current = null;
      }
    };
  }, [fetchInitialData]);

  // Node click from graph → open IncidentPanel
  const handleNodeClick = useCallback((deviceId: string) => {
    const device = devicesRef.current.find((d) => d.device_id === deviceId) ?? null;
    setSelectedDevice(device);
    const deviceAlert = alerts.find((a) => a.device_id === deviceId) ?? null;
    if (deviceAlert) setLatestAlert(deviceAlert);
  }, [alerts]);

  // Alert click → open IncidentPanel for that device
  const handleAlertClick = useCallback((alert: AlertEvent) => {
    const device = devicesRef.current.find((d) => d.device_id === alert.device_id) ?? null;
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
      const device = devicesRef.current.find((d) => d.device_id === frame.label) ?? null;
      setSelectedDevice(device);
    }
  }, [replayFrames, alerts]);

  // Determine graph enrichment for current replay frame
  const activeEnrichment = graphEnrichment;

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
            <span style={{ color: 'var(--risk-low)' }}>
              {wsStatus === 'live' ? 'Live WS' : wsStatus === 'mock' ? 'Mock WS' : 'WS offline'}
            </span>
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
          />

          {/* Right: Incident Panel (drill-down) or Alert Feed toggle */}
          {selectedDevice ? (
            <IncidentPanel
              device={selectedDevice}
              latestAlert={latestAlert}
              alerts={alerts}
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
