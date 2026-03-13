import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { X, Shield, Target, ArrowRight } from 'lucide-react';
import type { Device, AlertEvent, IncidentReport } from '../types/contracts';
import { MOCK_RISK_TREND, MOCK_INCIDENT_REPORT } from '../mocks/mockData';

interface IncidentPanelProps {
  device: Device | null;
  latestAlert: AlertEvent | null;
  onClose: () => void;
}

export function IncidentPanel({ device, latestAlert, onClose }: IncidentPanelProps) {
  const report: IncidentReport = MOCK_INCIDENT_REPORT;

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
    device.risk_score >= 80 ? 'critical'
    : device.risk_score >= 60 ? 'high'
    : device.risk_score >= 40 ? 'medium'
    : 'low';

  const chartColor =
    riskClass === 'critical' ? '#ef4444'
    : riskClass === 'high' ? '#f97316'
    : riskClass === 'medium' ? '#eab308'
    : '#22c55e';

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
            <AreaChart data={MOCK_RISK_TREND} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
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

        {/* Latest alert explanations */}
        {latestAlert && (
          <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 12, border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8 }}>Latest Alert Explanations</div>
            {latestAlert.reasons.map((r, i) => (
              <div key={i} style={{ fontSize: 12, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', gap: 6 }}>
                <span style={{ color: 'var(--risk-high)' }}>›</span> {r}
              </div>
            ))}
            <div style={{ marginTop: 8 }}>
              <span className="mitre-chip">
                {latestAlert.mitre.tactic} · {latestAlert.mitre.technique}
              </span>
            </div>
          </div>
        )}

        {/* Attack path */}
        {latestAlert && (
          <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 12, border: '1px solid rgba(239,68,68,0.25)' }}>
            <div style={{ fontSize: 11, color: 'var(--risk-critical)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Target size={12} /> Attack Path
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
              {latestAlert.graph.path.map((node, i) => (
                <React.Fragment key={node}>
                  <span style={{ fontSize: 11, color: 'var(--text-primary)', background: 'var(--bg-overlay)', borderRadius: 4, padding: '2px 6px' }} className="mono">
                    {node}
                  </span>
                  {i < latestAlert.graph.path.length - 1 && <ArrowRight size={10} style={{ color: 'var(--risk-critical)' }} />}
                </React.Fragment>
              ))}
            </div>
            {latestAlert.graph.next_targets.length > 0 && (
              <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-secondary)' }}>
                Next targets: <strong style={{ color: 'var(--risk-high)' }}>{latestAlert.graph.next_targets.join(', ')}</strong>
              </div>
            )}
          </div>
        )}

        {/* Recommendations */}
        <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 12, border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8 }}>Recommendations</div>
          {report.recommendations.map((rec, i) => (
            <div key={i} style={{ fontSize: 12, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', gap: 6 }}>
              <span style={{ color: 'var(--brand-from)' }}>{i + 1}.</span> {rec}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
