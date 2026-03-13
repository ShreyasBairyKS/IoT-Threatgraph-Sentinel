import type { AlertEvent, Device, GraphEnrichment } from '../types/contracts';

interface IncidentAnalysisModalProps {
  open: boolean;
  alert: AlertEvent | null;
  devices: Device[];
  enrichment: GraphEnrichment | null;
  onClose: () => void;
}

export function IncidentAnalysisModal({ open, alert, devices, enrichment, onClose }: IncidentAnalysisModalProps) {
  if (!open || !alert) return null;

  const impactedIds = new Set<string>([
    alert.device_id,
    ...alert.graph.path,
    ...alert.graph.next_targets,
    ...(enrichment?.neighbors ?? []),
    ...(enrichment?.attack_paths.flat() ?? []),
  ]);

  const impactedDevices = devices
    .filter((device) => impactedIds.has(device.device_id))
    .sort((a, b) => b.risk_score - a.risk_score);

  const topRisk = impactedDevices[0]?.risk_score ?? alert.risk_score;
  const avgRisk = impactedDevices.length > 0
    ? Math.round(impactedDevices.reduce((sum, d) => sum + d.risk_score, 0) / impactedDevices.length)
    : Math.round(alert.risk_score);

  const affectedCount = impactedIds.size;
  const pathsCount = enrichment?.attack_paths.length ?? 1;

  return (
    <div className="analysis-modal-backdrop" role="dialog" aria-modal="true" aria-label="Incident analysis">
      <div className="analysis-modal">
        <div className="analysis-modal-header">
          <div>
            <div className="analysis-title">Incident Analysis</div>
            <div className="analysis-subtitle">Clear explanation of what is happening and where it may spread next</div>
          </div>
          <button className="analysis-close-btn" onClick={onClose}>Close</button>
        </div>

        <div className="analysis-grid">
          <section className="analysis-card">
            <h3>What is happening</h3>
            <p>
              <strong>{alert.device_id}</strong> triggered a <strong>{alert.severity.toUpperCase()}</strong> alert with risk score <strong>{Math.round(alert.risk_score)}</strong>.
            </p>
            <ul>
              {alert.reasons.slice(0, 3).map((reason, index) => (
                <li key={index}>{reason}</li>
              ))}
            </ul>
            <p>
              MITRE mapping: <strong>{alert.mitre.tactic}</strong> ({alert.mitre.technique})
            </p>
          </section>

          <section className="analysis-card">
            <h3>How big is the impact</h3>
            <p>Affected devices: <strong>{affectedCount}</strong></p>
            <p>Likely attack paths: <strong>{pathsCount}</strong></p>
            <p>Highest impacted risk: <strong>{Math.round(topRisk)}</strong></p>
            <p>Average impacted risk: <strong>{avgRisk}</strong></p>
          </section>

          <section className="analysis-card">
            <h3>Likely spread</h3>
            <p>Immediate next targets:</p>
            <ul>
              {alert.graph.next_targets.length === 0 && <li>No immediate next targets identified.</li>}
              {alert.graph.next_targets.slice(0, 6).map((target) => (
                <li key={target}>{target}</li>
              ))}
            </ul>
          </section>

          <section className="analysis-card analysis-table-card">
            <h3>Impacted devices detail</h3>
            <div className="analysis-table">
              <div className="analysis-row analysis-head">
                <span>Device</span>
                <span>Type</span>
                <span>Risk</span>
                <span>Status</span>
              </div>
              {impactedDevices.slice(0, 12).map((device) => (
                <div key={device.device_id} className="analysis-row">
                  <span>{device.device_id}</span>
                  <span>{device.device_type}</span>
                  <span>{Math.round(device.risk_score)}</span>
                  <span>{device.status}</span>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
