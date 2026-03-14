import React, { useEffect, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { X, Shield, Target, ArrowRight, FileText, Download } from 'lucide-react';
import type { Device, AlertEvent, IncidentReport } from '../types/contracts';
import { MOCK_RISK_TREND } from '../mocks/mockData';

const API_BASE = 'http://localhost:8000';

interface IncidentPanelProps {
  device: Device | null;
  selectedAlert: AlertEvent | null;
  liveAlert: AlertEvent | null;
  alerts: AlertEvent[];
  onClose: () => void;
}

export function IncidentPanel({ device, selectedAlert, liveAlert, alerts, onClose }: IncidentPanelProps) {
  const [report, setReport] = useState<IncidentReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);

  // Fetch report for the pinned alert snapshot, not the moving live stream.
  useEffect(() => {
    if (!selectedAlert) { setReport(null); return; }
    setReportLoading(true);
    fetch(`${API_BASE}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(selectedAlert),
    })
      .then((r) => r.json())
      .then((data: IncidentReport) => { setReport(data); setReportLoading(false); })
      .catch(() => setReportLoading(false));
  }, [selectedAlert?.event_id]);

  if (!device) {
    return (
      <div className="panel" style={{ alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
        <div className="card-header" style={{ width: '100%' }}>
          <Shield size={14} className="icon" />
          Device Detail
        </div>
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 8 }}>
          <Shield size={32} style={{ opacity: 0.15 }} />
          <span>Select a device or alert</span>
        </div>
      </div>
    );
  }

  const riskClass =
      device.status === 'critical' ? 'critical'
      : device.status === 'suspicious' ? 'high'
      : device.confidence === 'medium' ? 'medium'
      : 'low';

  const chartColor =
    riskClass === 'critical' ? '#ef4444'
    : riskClass === 'high' ? '#f97316'
    : riskClass === 'medium' ? '#eab308'
    : '#22c55e';

  const deviceAlerts = alerts
    .filter((a) => a.device_id === device.device_id)
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  const computedTrend = deviceAlerts.map((a) => {
    const d = new Date(a.timestamp);
    return {
      time: `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`,
      risk: a.risk_score,
    };
  });

  const riskTrendData = computedTrend.length >= 2 
    ? computedTrend 
    : [...MOCK_RISK_TREND.slice(0, 6), { time: 'Now', risk: device.risk_score }];

  return (
    <div className="panel">
      {/* Header */}
      <div className="card-header">
        <Shield size={14} className="icon" />
        {device.device_id}
        <span className={`badge badge-${riskClass}`} style={{ marginLeft: 6 }}>{riskClass}</span>
        <button
          onClick={onClose}
          style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', display: 'flex' }}
        >
          <X size={14} />
        </button>
      </div>

      <div className="panel-body">
        {/* Risk score */}
        <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 14, border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 12 }}>
            <span style={{ color: 'var(--text-secondary)' }}>Risk Score</span>
            <span style={{ fontWeight: 700, fontSize: 22, color: chartColor }}>{device.risk_score}</span>
          </div>
          <div className="risk-bar-wrap" style={{ height: 6 }}>
            <div className="risk-bar-fill" style={{ width: `${device.risk_score}%`, background: chartColor }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, fontSize: 11, color: 'var(--text-secondary)' }}>
            <span>{device.device_type} · {device.status}</span>
            <span className={`badge badge-${device.confidence}`}>{device.confidence} confidence</span>
          </div>
        </div>

        {/* Trend chart */}
        <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: '12px 8px 8px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8, paddingLeft: 4 }}>Risk Trend (last 10 min)</div>
          <ResponsiveContainer width="100%" height={90}>
            <AreaChart data={riskTrendData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="rg" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={chartColor} stopOpacity={0.4} />
                  <stop offset="95%" stopColor={chartColor} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" tick={{ fontSize: 9, fill: '#71717a' }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: '#71717a' }} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 11 }}
                labelStyle={{ color: 'var(--text-secondary)' }}
              />
              <Area type="monotone" dataKey="risk" stroke={chartColor} fill="url(#rg)" strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Pinned alert snapshot */}
        {selectedAlert && (
          <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 12, border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8 }}>
              Pinned Alert Snapshot
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 8 }}>
              Event {selectedAlert.event_id} · {new Date(selectedAlert.timestamp).toLocaleString()}
            </div>
            {selectedAlert.reasons.map((r, i) => (
              <div key={i} style={{ fontSize: 12, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', gap: 6 }}>
                <span style={{ color: 'var(--risk-high)' }}>›</span> {r}
              </div>
            ))}
            <div style={{ marginTop: 8 }}>
              <span className="mitre-chip">
                {selectedAlert.mitre.tactic} · {selectedAlert.mitre.technique}
              </span>
            </div>
          </div>
        )}

        {/* Live stream context */}
        {liveAlert && (
          <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 12, border: '1px solid rgba(34,197,94,0.25)' }}>
            <div style={{ fontSize: 11, color: 'var(--risk-low)', marginBottom: 8 }}>
              Live Stream Right Now
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 11 }}>
              <span style={{ color: 'var(--text-primary)' }}>{liveAlert.device_id}</span>
              <span className={`badge badge-${liveAlert.severity === 'critical' ? 'critical' : liveAlert.severity === 'high' ? 'high' : liveAlert.severity === 'medium' ? 'medium' : 'low'}`}>
                {liveAlert.severity}
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              {liveAlert.reasons[0] ?? 'No explanation available'}
            </div>
          </div>
        )}

        {/* Attack path */}
        {selectedAlert && (
          <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 12, border: '1px solid rgba(239,68,68,0.25)' }}>
            <div style={{ fontSize: 11, color: 'var(--risk-critical)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Target size={12} /> Attack Path
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
              {selectedAlert.graph.path.map((node, i) => (
                <React.Fragment key={node}>
                  <span style={{ fontSize: 11, color: 'var(--text-primary)', background: 'var(--bg-overlay)', borderRadius: 4, padding: '2px 6px' }} className="mono">
                    {node}
                  </span>
                  {i < selectedAlert.graph.path.length - 1 && <ArrowRight size={10} style={{ color: 'var(--risk-critical)' }} />}
                </React.Fragment>
              ))}
            </div>
            {selectedAlert.graph.next_targets.length > 0 && (
              <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-secondary)' }}>
                Next targets: <strong style={{ color: 'var(--risk-high)' }}>{selectedAlert.graph.next_targets.join(', ')}</strong>
              </div>
            )}
          </div>
        )}

        {/* Recommendations + PDF download */}
        <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 12, border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 5 }}>
              <FileText size={11} /> Recommendations
            </div>
            {selectedAlert && (
              <a
                href={`${API_BASE}/report/${selectedAlert.event_id}/pdf`}
                target="_blank"
                rel="noreferrer"
                style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  fontSize: 11, color: 'var(--brand-from)', textDecoration: 'none',
                  background: 'rgba(99,102,241,0.12)', borderRadius: 4, padding: '2px 8px',
                }}
              >
                <Download size={10} /> PDF
              </a>
            )}
          </div>

          {reportLoading && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Generating report…</div>
          )}

          {!reportLoading && report && report.recommendations.map((rec, i) => (
            <div key={i} style={{ fontSize: 12, color: 'var(--text-primary)', marginBottom: 6, display: 'flex', gap: 6 }}>
              <span style={{ color: 'var(--brand-from)', flexShrink: 0 }}>{i + 1}.</span> {rec}
            </div>
          ))}

          {!reportLoading && report && (
            <div style={{ marginTop: 8, fontSize: 10, color: 'var(--text-muted)' }}>
              Report ID: <span className="mono">{report.report_id}</span>
              {' · '}{report.affected_devices.length} device(s) affected
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
