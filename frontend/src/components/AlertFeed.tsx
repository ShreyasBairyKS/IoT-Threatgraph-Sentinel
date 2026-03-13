import { Bell, AlertTriangle, Info, ShieldCheck } from 'lucide-react';
import type { AlertEvent, Device } from '../types/contracts';

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
  selected: boolean;
  onClick: () => void;
}

function AlertCard({ alert, selected, onClick }: AlertCardProps) {
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
        background: selected ? 'rgba(99,102,241,0.12)' : 'var(--bg-elevated)',
        border: `1px solid ${selected ? 'rgba(129,140,248,0.55)' : 'var(--border)'}`,
        borderRadius: 'var(--radius-md)',
        padding: '10px 12px',
        textAlign: 'left',
        cursor: 'pointer',
        transition: 'border-color var(--transition), background var(--transition)',
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
  devices: Device[];
  onAlertClick: (alert: AlertEvent) => void;
  selectedAlertId?: string | null;
}

export function AlertFeed({ alerts, devices, onAlertClick, selectedAlertId = null }: AlertFeedProps) {
  const visibleAlerts = alerts.slice(0, 30);
  const quietDevices = devices
    .filter((device) => device.risk_score < 60)
    .sort((a, b) => a.risk_score - b.risk_score)
    .slice(0, 6);

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

        {visibleAlerts.map((a) => (
          <AlertCard
            key={a.event_id + a.timestamp}
            alert={a}
            selected={selectedAlertId === a.event_id}
            onClick={() => onAlertClick(a)}
          />
        ))}

        <div
          style={{
            marginTop: 8,
            background: 'var(--bg-elevated)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            padding: '10px 12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, fontSize: 11, color: 'var(--text-secondary)' }}>
            <ShieldCheck size={12} style={{ color: 'var(--risk-normal)' }} />
            Monitored With No Active Alert
          </div>

          {quietDevices.length === 0 && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              All monitored devices currently have active alerts.
            </div>
          )}

          {quietDevices.map((device) => (
            <div
              key={device.device_id}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '6px 0',
                borderTop: '1px solid rgba(255,255,255,0.04)',
                fontSize: 12,
              }}
            >
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <span style={{ color: 'var(--text-primary)' }}>{device.device_id}</span>
                <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
                  {device.device_type} · {device.status}
                </span>
              </div>
              <span style={{ color: 'var(--risk-normal)', fontWeight: 600 }}>
                {device.risk_score}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
