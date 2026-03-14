import { useEffect, useState } from 'react';
import { ArrowLeft, ShieldAlert, Target, ActivitySquare, FileText, Download } from 'lucide-react';
import type { AlertEvent, Device, GraphEnrichment, IncidentReport } from '../types/contracts';
import { ThreatGraph } from './ThreatGraph';

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)
  ?? `${window.location.protocol}//${window.location.hostname}:8000`;

interface IncidentDetailPageProps {
  alert: AlertEvent;
  devices: Device[];
  enrichment: GraphEnrichment;
  onBack: () => void;
  onSelectDevice: (deviceId: string) => void;
}

export function IncidentDetailPage({
  alert,
  devices,
  enrichment,
  onBack,
  onSelectDevice,
}: IncidentDetailPageProps) {
  const [report, setReport] = useState<IncidentReport | null>(null);
  const [reportEventId, setReportEventId] = useState<string | null>(null);

  const reportLoading = reportEventId !== alert.event_id;

  useEffect(() => {
    const currentEventId = alert.event_id;
    fetch(`${API_BASE}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
    })
      .then((response) => response.json())
      .then((data: IncidentReport) => {
        setReport(data);
        setReportEventId(currentEventId);
      })
      .catch(() => {
        setReport(null);
        setReportEventId(currentEventId);
      });
  }, [alert]);

  const impactedIds = new Set<string>([
    alert.device_id,
    ...alert.graph.path,
    ...alert.graph.next_targets,
    ...enrichment.neighbors,
    ...enrichment.attack_paths.flat(),
  ]);

  const impactedDevices = devices
    .filter((device) => impactedIds.has(device.device_id))
    .sort((a, b) => b.risk_score - a.risk_score);

  return (
    <div className="incident-page">
      <div className="incident-topbar">
        <button className="btn btn-ghost" onClick={onBack}>
          <ArrowLeft size={14} /> Back to Dashboard
        </button>

        <div className="incident-title-wrap">
          <div className="incident-title">Incident Deep Analysis</div>
          <div className="incident-subtitle">
            Event {alert.event_id} · {alert.device_id} · {alert.severity.toUpperCase()} · Risk {Math.round(alert.risk_score)}
          </div>
        </div>

        <a
          className="incident-pdf-btn"
          href={`${API_BASE}/report/${alert.event_id}/pdf`}
          target="_blank"
          rel="noreferrer"
          style={{ marginLeft: 'auto' }}
        >
          <Download size={14} /> Download Incident PDF
        </a>
      </div>

      <div className="incident-summary-grid">
        <div className="incident-summary-card">
          <div className="incident-summary-label">Attack Source</div>
          <div className="incident-summary-value">{alert.device_id}</div>
        </div>
        <div className="incident-summary-card">
          <div className="incident-summary-label">Impacted Devices</div>
          <div className="incident-summary-value">{impactedIds.size}</div>
        </div>
        <div className="incident-summary-card">
          <div className="incident-summary-label">Predicted Next Targets</div>
          <div className="incident-summary-value">{alert.graph.next_targets.length}</div>
        </div>
        <div className="incident-summary-card">
          <div className="incident-summary-label">Propagation Risk</div>
          <div className="incident-summary-value">{Math.round(enrichment.propagation_risk * 100)}%</div>
        </div>
      </div>

      <div className="incident-main-grid">
        <div className="incident-graph-wrap">
          <ThreatGraph
            devices={devices}
            enrichment={enrichment}
            onNodeClick={onSelectDevice}
            title="Incident Attack Graph"
            subtitle="full-size focused incident spread"
            mode="focus"
            highlightedDeviceId={alert.device_id}
          />
        </div>

        <div className="incident-side-wrap">
          <div className="incident-side-card">
            <div className="incident-card-title"><ShieldAlert size={15} /> What is happening</div>
            <ul className="incident-list">
              {alert.reasons.map((reason, index) => (
                <li key={index}>{reason}</li>
              ))}
            </ul>
            <div className="incident-mitre">MITRE: {alert.mitre.tactic} · {alert.mitre.technique}</div>
          </div>

          <div className="incident-side-card">
            <div className="incident-card-title"><FileText size={15} /> Recommendations</div>
            {reportLoading && (
              <div className="incident-helper-text">Generating report recommendations…</div>
            )}
            {!reportLoading && report && report.recommendations.length > 0 && (
              <ol className="incident-recommendations">
                {report.recommendations.map((recommendation, index) => (
                  <li key={index}>{recommendation}</li>
                ))}
              </ol>
            )}
            {!reportLoading && !report && (
              <div className="incident-helper-text">Recommendations unavailable for this alert.</div>
            )}
            <a
              className="incident-pdf-btn"
              href={`${API_BASE}/report/${alert.event_id}/pdf`}
              target="_blank"
              rel="noreferrer"
            >
              <Download size={14} /> Download Incident PDF
            </a>
          </div>

          <div className="incident-side-card">
            <div className="incident-card-title"><Target size={15} /> Attack paths</div>
            <div className="incident-paths">
              {enrichment.attack_paths.slice(0, 8).map((path, index) => (
                <div key={index} className="incident-path">{path.join(' → ')}</div>
              ))}
            </div>
          </div>

          <div className="incident-side-card">
            <div className="incident-card-title"><ActivitySquare size={15} /> Impacted devices</div>
            <div className="incident-device-table">
              <div className="incident-device-head">
                <span>Device</span>
                <span>Type</span>
                <span>Risk</span>
              </div>
              {impactedDevices.slice(0, 14).map((device) => (
                <button
                  key={device.device_id}
                  className="incident-device-row"
                  onClick={() => onSelectDevice(device.device_id)}
                >
                  <span>{device.device_id}</span>
                  <span>{device.device_type}</span>
                  <span>{Math.round(device.risk_score)}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
