import { Bell, AlertTriangle, Info } from 'lucide-react';
import type { AlertEvent } from '../types/contracts';

// ── Helpers ───────────────────────────────────────────────────────────────
function timeAgo(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function severityIcon(severity: string) {
  if (severity === 'critical' || severity === 'high') return <AlertTriangle size={12} />;
  return <Info size={12} />;
}

// ── Single alert card ─────────────────────────────────────────────────────
interface AlertCardProps {
  alert: AlertEvent;
  onClick: () => void;
}

function AlertCard({ alert, onClick }: AlertCardProps) {
  const bClass =
    alert.severity === 'critical' ? 'critical'
    : alert.severity === 'high' ? 'high'
    : alert.severity === 'medium' ? 'medium'
    : 'low';

  return (
    <button
      className="alert-item"
      onClick={onClick}
      style={{
        width: '100%',
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        padding: '10px 12px',
        textAlign: 'left',
        cursor: 'pointer',
        transition: 'border-color var(--transition)',
      }}
      onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.borderColor = 'var(--border-accent)'; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'; }}
    >
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className={`badge badge-${bClass}`}>
            {severityIcon(alert.severity)}
            {alert.severity}
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            {alert.device_id}
          </span>
        </div>
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{timeAgo(alert.timestamp)}</span>
      </div>

      {/* Explanations */}
      {alert.reasons.map((r, i) => (
        <div key={i} style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 2, paddingLeft: 2 }}>
          • {r}
        </div>
      ))}

      {/* Footer: MITRE tag + risk score */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 8 }}>
        <span className="mitre-chip">
          {alert.mitre.tactic} · {alert.mitre.technique}
        </span>
        <span style={{ fontSize: 12, fontWeight: 600, color: bClass === 'critical' || bClass === 'high' ? 'var(--risk-high)' : 'var(--text-secondary)' }}>
          {alert.risk_score}
        </span>
      </div>
    </button>
  );
}

// ── Component ─────────────────────────────────────────────────────────────
interface AlertFeedProps {
  alerts: AlertEvent[];
  onAlertClick: (alert: AlertEvent) => void;
}

export function AlertFeed({ alerts, onAlertClick }: AlertFeedProps) {
  return (
    <div className="panel">
      <div className="card-header">
        <Bell size={14} className="icon" />
        Alert Feed
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--risk-high)', fontWeight: 600 }}>
          {alerts.length} active
        </span>
      </div>
      <div className="panel-body">
        {alerts.length === 0 && (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 12, marginTop: 40 }}>
            No alerts. All clear.
          </div>
        )}
        {[...alerts].reverse().map((a) => (
          <AlertCard key={a.event_id + a.timestamp} alert={a} onClick={() => onAlertClick(a)} />
        ))}
      </div>
    </div>
  );
}
