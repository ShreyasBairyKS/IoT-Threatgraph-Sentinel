import { useEffect, useRef, useState, useCallback } from 'react';
import './index.css';

import { DeviceList } from './components/DeviceList';
import { ThreatGraph } from './components/ThreatGraph';
import { AlertFeed } from './components/AlertFeed';
import { IncidentPanel } from './components/IncidentPanel';
import { ReplayTimeline } from './components/ReplayTimeline';
import { SimulateThreatPanel } from './components/SimulateThreatPanel';
import { buildReplayFrames } from './components/replayUtils';

import { MockWebSocket } from './mocks/mockWebSocket';
import {
  MOCK_DEVICES,
  MOCK_ALERTS,
  MOCK_GRAPH_ENRICHMENT,
} from './mocks/mockData';

import type { AlertEvent, Device } from './types/contracts';
import type { GraphEnrichment } from './types/contracts';
import { Activity, Wifi, FlaskConical } from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';
const WS_URL = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000/ws/alerts';
const MOCKS_ENABLED = import.meta.env.VITE_ENABLE_MOCK_FALLBACK === 'true';

// ── App ────────────────────────────────────────────────────────────────────
export default function App() {
  // State
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [feedEvents, setFeedEvents] = useState<AlertEvent[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [graphEnrichment, setGraphEnrichment] = useState<GraphEnrichment | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [latestAlert, setLatestAlert] = useState<AlertEvent | null>(null);
  const [replayIndex, setReplayIndex] = useState(0);
  const [wsStatus, setWsStatus] = useState<'live' | 'mock' | 'offline'>('offline');
  const [showSimulator, setShowSimulator] = useState(false);
  const [compromiseToast, setCompromiseToast] = useState<string | null>(null);
  const toastTimerRef = useRef<number | null>(null);

  // Build replay frames from alerts
  const replayFrames = buildReplayFrames(alerts);

  // Keep refs to avoid stale closures in WS listeners.
  const devicesRef = useRef<Device[]>([]);
  useEffect(() => {
    devicesRef.current = devices;
  }, [devices]);

  const refreshGraph = useCallback(async () => {
    try {
      const graphRes = await fetch(`${API_BASE_URL}/graph`);
      if (!graphRes.ok) {
        return;
      }
      const liveGraph = await graphRes.json() as GraphEnrichment;
      setGraphEnrichment(liveGraph ?? null);
    } catch {
      // Keep existing graph state when refresh fails.
    }
  }, []);

  const refreshFeed = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/feed?limit=300`);
      if (res.ok) {
        const data = await res.json() as AlertEvent[];
        setFeedEvents(data);
      }
    } catch {
      // keep existing feed state on transient failure
    }
  }, []);

  const fetchInitialData = useCallback(async () => {
    try {
      const [devicesRes, alertsRes, graphRes, feedRes] = await Promise.all([
        fetch(`${API_BASE_URL}/devices`),
        fetch(`${API_BASE_URL}/alerts`),
        fetch(`${API_BASE_URL}/graph`),
        fetch(`${API_BASE_URL}/feed?limit=300`),
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

      if (feedRes.ok) {
        const liveFeed = await feedRes.json() as AlertEvent[];
        setFeedEvents(liveFeed);
      }
    } catch {
      if (MOCKS_ENABLED) {
        setDevices(MOCK_DEVICES);
        setAlerts(MOCK_ALERTS);
        setFeedEvents(MOCK_ALERTS);
        setGraphEnrichment(MOCK_GRAPH_ENRICHMENT);
        setLatestAlert(MOCK_ALERTS[0] ?? null);
        setWsStatus('mock');
      } else {
        setDevices([]);
        setAlerts([]);
        setFeedEvents([]);
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

      // Optimistically reflect graph details included in the live alert,
      // then reconcile with backend /graph for the latest enrichment snapshot.
      setGraphEnrichment({
        timestamp: evt.timestamp,
        source_device: evt.device_id,
        propagation_risk: Math.max(0, Math.min(1, evt.risk_score / 100)),
        neighbors: evt.graph.next_targets,
        next_target_prediction: evt.graph.next_targets.map((id) => ({
          device_id: id,
          score: 0.5,
          why: 'derived from alert event',
        })),
        attack_paths: [evt.graph.path],
        mitre: evt.mitre,
      });
      void refreshGraph();

      if (evt.severity === 'high' || evt.severity === 'critical') {
        const message = `${evt.device_id} device has been compromised via ${evt.mitre.tactic} (${evt.mitre.technique}).`;
        setCompromiseToast(message);
        if (toastTimerRef.current !== null) {
          window.clearTimeout(toastTimerRef.current);
        }
        toastTimerRef.current = window.setTimeout(() => {
          setCompromiseToast(null);
          toastTimerRef.current = null;
        }, 4800);
      }

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

    // Poll /feed every 10 s so all-severity events stay fresh
    const feedInterval = window.setInterval(() => { void refreshFeed(); }, 10_000);

    return () => {
      window.clearInterval(feedInterval);
      if (liveWsRef.current) {
        liveWsRef.current.close();
        liveWsRef.current = null;
      }
      if (fallbackWs) {
        fallbackWs.disconnect();
        wsRef.current = null;
      }
      if (toastTimerRef.current !== null) {
        window.clearTimeout(toastTimerRef.current);
        toastTimerRef.current = null;
      }
    };
  }, [fetchInitialData, refreshGraph, refreshFeed]);

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
          <button
            className="btn btn-ghost"
            type="button"
            onClick={() => setShowSimulator((prev) => !prev)}
            aria-label="Toggle threat simulator"
          >
            <FlaskConical size={12} />
            {showSimulator ? 'Hide Simulator' : 'Simulate Threat'}
          </button>
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
              feedEvents={feedEvents}
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

      <SimulateThreatPanel
        open={showSimulator}
        devices={devices}
        apiBaseUrl={API_BASE_URL}
        onGraphInjected={(enrichment) => {
          setGraphEnrichment(enrichment);
          void refreshGraph();
          // Refresh feed shortly after so manual simulation shows in All Feed
          window.setTimeout(() => { void refreshFeed(); }, 600);
        }}
        onClose={() => setShowSimulator(false)}
      />

      {compromiseToast && (
        <div className="compromise-toast" role="status" aria-live="polite">
          {compromiseToast}
        </div>
      )}
    </div>
  );
}
