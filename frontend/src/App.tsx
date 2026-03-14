import { useEffect, useRef, useState, useCallback } from 'react';
import './index.css';

import { DeviceList } from './components/DeviceList';
import { ThreatGraph } from './components/ThreatGraph';
import { AlertFeed } from './components/AlertFeed';
import { IncidentPanel } from './components/IncidentPanel';
import { ReplayTimeline } from './components/ReplayTimeline';
import { buildReplayFrames } from './components/replayUtils';

import { MOCK_GRAPH_ENRICHMENT } from './mocks/mockData';
import type { AlertEvent, Device, GraphEnrichment } from './types/contracts';
import { Activity, Wifi } from 'lucide-react';

const API_BASE = 'http://localhost:8000';
const WS_URL = 'ws://localhost:8000/ws/alerts';

interface AlertGraphSnapshot {
  devices: Device[];
  enrichment: GraphEnrichment;
}

function buildEnrichmentFromAlert(alert: AlertEvent, why: string): GraphEnrichment {
  return {
    timestamp: alert.timestamp,
    source_device: alert.device_id,
    propagation_risk: alert.risk_score / 100,
    neighbors: alert.graph.next_targets,
    next_target_prediction: alert.graph.next_targets.map((id) => ({ device_id: id, score: 0.82, why })),
    attack_paths: [alert.graph.path],
    mitre: alert.mitre,
  };
}

function buildSnapshot(alert: AlertEvent, sourceDevices: Device[], why: string): AlertGraphSnapshot {
  return {
    devices: sourceDevices.map((device) => ({ ...device })),
    enrichment: buildEnrichmentFromAlert(alert, why),
  };
}

// ── App ────────────────────────────────────────────────────────────────────
export default function App() {
  // State
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [liveAlert, setLiveAlert] = useState<AlertEvent | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<AlertEvent | null>(null);
  const [replayIndex, setReplayIndex] = useState(0);
  const [wsStatus, setWsStatus] = useState<'live' | 'connecting' | 'disconnected'>('connecting');
  const [alertSnapshots, setAlertSnapshots] = useState<Record<string, AlertGraphSnapshot>>({});
  const [summary, setSummary] = useState({
    total_submissions: 0,
    alert_submissions: 0,
    non_alert_submissions: 0,
  });
  const [baseEnrichment, setBaseEnrichment] = useState<GraphEnrichment>(MOCK_GRAPH_ENRICHMENT);

  // Build replay frames from alerts
  const replayFrames = buildReplayFrames(alerts);

  // Live WebSocket
  const wsRef = useRef<WebSocket | null>(null);

  // Fetch initial alerts + devices from API
  useEffect(() => {
    const loadSummary = () => {
      fetch(`${API_BASE}/metrics/summary`)
        .then((r) => r.json())
        .then((data) => setSummary(data))
        .catch(() => {});
    };

    const loadDevices = () => {
      fetch(`${API_BASE}/devices`)
        .then((r) => r.json())
        .then((data: Device[]) => setDevices(data))
        .catch(() => {});
    };

    const loadGraph = () => {
      fetch(`${API_BASE}/graph`)
        .then((r) => r.json())
        .then((data: GraphEnrichment) => setBaseEnrichment(data))
        .catch(() => setBaseEnrichment(MOCK_GRAPH_ENRICHMENT));
    };

    fetch(`${API_BASE}/alerts`)
      .then((r) => r.json())
      .then((data: AlertEvent[]) => {
        const recentAlerts = data.slice(0, 50);
        setAlerts(recentAlerts);
        if (recentAlerts.length > 0) {
          setLiveAlert(recentAlerts[0]);
        }
      })
      .catch(() => {});

    loadDevices();
    loadSummary();
    loadGraph();

    const pollId = window.setInterval(() => {
      loadDevices();
      loadSummary();
      loadGraph();
    }, 4000);

    return () => window.clearInterval(pollId);
  }, []);

  useEffect(() => {
    if (devices.length === 0 || alerts.length === 0) return;

    setAlertSnapshots((prev) => {
      const next = { ...prev };
      for (const alert of alerts) {
        if (!next[alert.event_id]) {
          next[alert.event_id] = buildSnapshot(alert, devices, 'historical snapshot');
        }
      }
      return next;
    });
  }, [alerts, devices]);

  // Real WebSocket connection
  useEffect(() => {
    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => setWsStatus('live');
      ws.onclose = () => {
        setWsStatus('disconnected');
        // Reconnect after 3s
        setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();

      ws.onmessage = (event) => {
        try {
          const evt: AlertEvent = JSON.parse(event.data);
          setAlerts((prev) => {
            if (prev.some((a) => a.event_id === evt.event_id)) return prev;
            return [evt, ...prev].slice(0, 100);
          });
          setLiveAlert(evt);
          // Refresh devices list to pick up risk score changes
          fetch(`${API_BASE}/devices`)
            .then((r) => r.json())
            .then((data: Device[]) => {
              setDevices(data);
              setAlertSnapshots((prev) => ({
                ...prev,
                [evt.event_id]: buildSnapshot(evt, data, 'live snapshot'),
              }));
            })
            .catch(() => {});
          fetch(`${API_BASE}/metrics/summary`)
            .then((r) => r.json())
            .then((data) => setSummary(data))
            .catch(() => {});
        } catch (_) {}
      };
    }

    connect();
    return () => {
      wsRef.current?.close();
    };
  }, []);

  // Node click from graph → open IncidentPanel
  const handleNodeClick = useCallback((deviceId: string) => {
    const device = devices.find((d) => d.device_id === deviceId) ?? null;
    setSelectedDevice(device);
    const deviceAlert = alerts.find((a) => a.device_id === deviceId) ?? null;
    setSelectedAlert(deviceAlert);
  }, [alerts, devices]);

  // Alert click → open IncidentPanel for that device
  const handleAlertClick = useCallback((alert: AlertEvent) => {
    const device = devices.find((d) => d.device_id === alert.device_id) ?? null;
    setSelectedDevice(device);
    setSelectedAlert(alert);

    fetch(`${API_BASE}/alerts/${alert.event_id}/context`)
      .then((response) => {
        if (!response.ok) {
          throw new Error('No saved context');
        }
        return response.json();
      })
      .then((context) => {
        if (!context?.devices || !context?.enrichment) return;
        setAlertSnapshots((prev) => ({
          ...prev,
          [alert.event_id]: {
            devices: context.devices,
            enrichment: context.enrichment,
          },
        }));
      })
      .catch(() => {});
  }, [devices]);

  // Device click from list → open IncidentPanel
  const handleDeviceSelect = useCallback((device: Device) => {
    setSelectedDevice(device);
    const deviceAlert = alerts.find((a) => a.device_id === device.device_id) ?? null;
    setSelectedAlert(deviceAlert);
  }, [alerts]);

  // Replay-index change → highlight the alert at that frame
  const handleReplayChange = useCallback((index: number) => {
    setReplayIndex(index);
    const frame = replayFrames[index];
    if (!frame) return;
    const correspondingAlert = alerts.find((a) => a.device_id === frame.label) ?? null;
    if (correspondingAlert) {
      setSelectedAlert(correspondingAlert);
      const device = devices.find((d) => d.device_id === frame.label) ?? null;
      setSelectedDevice(device);
    }
  }, [replayFrames, alerts, devices]);

  const liveSnapshot = liveAlert ? alertSnapshots[liveAlert.event_id] : null;
  const selectedSnapshot = selectedAlert ? alertSnapshots[selectedAlert.event_id] : null;

  // Derive graph enrichment from live alert for the threat graph
  const activeEnrichment: GraphEnrichment = liveSnapshot?.enrichment ?? (liveAlert
    ? buildEnrichmentFromAlert(liveAlert, 'live feed') 
    : baseEnrichment);

  const liveGraphDevices = liveSnapshot?.devices ?? devices;

  const selectedEnrichment: GraphEnrichment | null = selectedSnapshot?.enrichment ?? (selectedAlert
    ? buildEnrichmentFromAlert(selectedAlert, 'selected incident')
    : null);
  const selectedGraphDevices = selectedSnapshot?.devices ?? devices;

  const totalSubmittedCount = summary.total_submissions;
  const alertingCount = summary.alert_submissions;
  const quietCount = summary.non_alert_submissions;

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
            <Wifi size={12} style={{ color: wsStatus === 'live' ? 'var(--risk-low)' : wsStatus === 'connecting' ? 'var(--risk-medium)' : 'var(--risk-critical)' }} />
            <span style={{ color: wsStatus === 'live' ? 'var(--risk-low)' : wsStatus === 'connecting' ? 'var(--risk-medium)' : 'var(--risk-critical)' }}>
              {wsStatus === 'live' ? 'Live' : wsStatus === 'connecting' ? 'Connecting…' : 'Reconnecting…'}
            </span>
          </span>
          <span className="mono" style={{ fontSize: 11 }}>
            {new Date().toLocaleTimeString()}
          </span>
        </div>
      </header>

      {/* ── Three-panel main content ─────────────────────────────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', flex: 1 }}>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
            gap: 10,
            padding: '10px 12px 0',
          }}
        >
          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '10px 12px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>Data Submitted</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>{totalSubmittedCount}</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Tracked devices / data sources received</div>
          </div>

          <div style={{ background: 'var(--bg-elevated)', border: '1px solid rgba(249,115,22,0.28)', borderRadius: 'var(--radius-md)', padding: '10px 12px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>Generating Alerts</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--risk-high)' }}>{alertingCount}</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Devices currently in active or elevated state</div>
          </div>

          <div style={{ background: 'var(--bg-elevated)', border: '1px solid rgba(34,197,94,0.24)', borderRadius: 'var(--radius-md)', padding: '10px 12px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>No Alerts</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--risk-normal)' }}>{quietCount}</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Devices submitting data without active alerts</div>
          </div>
        </div>

        <div className="main-content" style={{ flex: 1 }}>
          {/* Left: Device List */}
          <DeviceList
            devices={devices}
            selectedId={selectedDevice?.device_id ?? null}
            onSelect={handleDeviceSelect}
          />

          <div
            className="graph-stack"
            style={{
              gridTemplateRows: selectedEnrichment
                ? 'minmax(280px, 1fr) minmax(220px, 0.85fr)'
                : 'minmax(320px, 1fr)',
            }}
          >
            <ThreatGraph
              devices={liveGraphDevices}
              enrichment={activeEnrichment}
              onNodeClick={handleNodeClick}
              title="Live Threat Graph"
              subtitle="always-on real-time topology"
              mode="live"
              highlightedDeviceId={liveAlert?.device_id ?? null}
            />

            {selectedEnrichment && (
              <ThreatGraph
                devices={selectedGraphDevices}
                enrichment={selectedEnrichment}
                onNodeClick={handleNodeClick}
                title="Selected Incident Graph"
                subtitle={selectedAlert ? `${selectedAlert.device_id} · ${selectedAlert.event_id}` : 'focused incident view'}
                mode="focus"
                highlightedDeviceId={selectedAlert?.device_id ?? null}
              />
            )}
          </div>

          <div
            className="right-stack"
            style={{
              gridTemplateRows: selectedDevice
                ? 'minmax(260px, 1fr) minmax(300px, 1fr)'
                : 'minmax(320px, 1fr) minmax(220px, 0.75fr)',
            }}
          >
            <AlertFeed
              alerts={alerts}
              devices={devices}
              onAlertClick={handleAlertClick}
              selectedAlertId={selectedAlert?.event_id ?? null}
            />

            <IncidentPanel
              device={selectedDevice}
              selectedAlert={selectedAlert}
              liveAlert={liveAlert}
              alerts={alerts}
              onClose={() => {
                setSelectedDevice(null);
                setSelectedAlert(null);
              }}
            />
          </div>
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
