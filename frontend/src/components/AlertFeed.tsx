import { useState } from 'react';
import { Bell, AlertTriangle, Info, Radio } from 'lucide-react';
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

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--risk-critical, #e53e3e)',
  high: 'var(--risk-high, #dd6b20)',
  medium: 'var(--risk-medium, #d69e2e)',
  low: 'var(--risk-low, #38a169)',
};

function riskBar(score: number, severity: string) {
  return (
    <div
      title={`Risk ${score.toFixed(1)}`}
      style={{
        height: 4,
        borderRadius: 2,
        background: `linear-gradient(to right, ${SEVERITY_COLOR[severity] ?? 'var(--border-accent)'} ${score}%, var(--bg-elevated) ${score}%)`,
        marginBottom: 6,
      }}
    />
  );
}

// ── Single event card ─────────────────────────────────────────────────────
interface EventCardProps {
  event: AlertEvent;
  selected?: boolean;
  onClick: () => void;
}

function EventCard({ event, onClick, selected = false }: EventCardProps) {
  const sev = event.severity;
  const bClass = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low';

  // Strip internal source tag from display
  const displayReasons = event.reasons.filter((r) => !r.startsWith('source:'));
  const sourceTag = event.reasons.find((r) => r.startsWith('source:'))?.replace('source:', '') ?? null;

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
        transition: 'border-color var(--transition)',
      }}
      onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.borderColor = 'var(--border-accent)'; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.borderColor = selected ? 'rgba(129,140,248,0.55)' : 'var(--border)'; }}
    >
      {riskBar(event.risk_score, sev)}

      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <span className={`badge badge-${bClass}`}>
            {severityIcon(sev)}
            {sev}
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontWeight: 500 }}>
            {event.device_id}
          </span>
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
            {event.device_type}
          </span>
          {sourceTag && (
            <span style={{
              fontSize: 9,
              color: sourceTag === 'simulator' ? 'var(--risk-medium, #d69e2e)' : 'var(--text-muted)',
              border: '1px solid currentColor',
              borderRadius: 3,
              padding: '0 4px',
              lineHeight: '16px',
            }}>
              {sourceTag === 'simulator' ? '⚡ manual' : sourceTag}
            </span>
          )}
        </div>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          {timeAgo(event.timestamp)}
        </span>
      </div>

      {/* Risk + confidence row */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 4, fontSize: 11, color: 'var(--text-muted)' }}>
        <span style={{ fontWeight: 600, color: SEVERITY_COLOR[sev] }}>
          Risk {event.risk_score.toFixed(1)}
        </span>
        <span>conf: {event.confidence}</span>
      </div>

      {/* Reasons */}
      {displayReasons.slice(0, 2).map((r, i) => (
        <div key={i} style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2, paddingLeft: 2 }}>
          • {r}
        </div>
      ))}

      {/* Footer: MITRE */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 6 }}>
        <span className="mitre-chip">
          {event.mitre.tactic} · {event.mitre.technique}
        </span>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
          {event.event_id}
        </span>
      </div>
    </button>
  );
}

// ── Component ─────────────────────────────────────────────────────────────
interface AlertFeedProps {
  /** Thresholded alerts (high/critical): from /alerts WS stream */
  alerts: AlertEvent[];
  /** All-severity feed events: from /feed polling */
  feedEvents: AlertEvent[];
  onAlertClick: (alert: AlertEvent) => void;
  /** Highlight the currently selected alert */
  selectedAlertId?: string | null;
}

type Tab = 'all' | 'alerts';

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function AlertFeed({ alerts, feedEvents, onAlertClick, selectedAlertId = null }: AlertFeedProps) {
  const [tab, setTab] = useState<Tab>('all');

  const allEvents = [...feedEvents].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );
  const alertEvents = [...alerts].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9),
  );

  const items = tab === 'all' ? allEvents : alertEvents;

  const critCount = allEvents.filter((e) => e.severity === 'critical').length;
  const highCount = allEvents.filter((e) => e.severity === 'high').length;
  const medCount  = allEvents.filter((e) => e.severity === 'medium').length;
  const lowCount  = allEvents.filter((e) => e.severity === 'low').length;

  return (
    <div className="panel" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── Summary bar ─────────────────────────────────────────────── */}
      <div style={{
        display: 'flex',
        gap: 6,
        padding: '6px 12px',
        borderBottom: '1px solid var(--border)',
        fontSize: 11,
        flexWrap: 'wrap',
        background: 'var(--bg-elevated)',
      }}>
        <span style={{ color: SEVERITY_COLOR.critical, fontWeight: 700 }}>{critCount} critical</span>
        <span style={{ color: 'var(--text-muted)' }}>·</span>
        <span style={{ color: SEVERITY_COLOR.high, fontWeight: 600 }}>{highCount} high</span>
        <span style={{ color: 'var(--text-muted)' }}>·</span>
        <span style={{ color: SEVERITY_COLOR.medium }}>{medCount} medium</span>
        <span style={{ color: 'var(--text-muted)' }}>·</span>
        <span style={{ color: SEVERITY_COLOR.low }}>{lowCount} low</span>
      </div>

      {/* ── Tab bar ─────────────────────────────────────────────────── */}
      <div style={{
        display: 'flex',
        borderBottom: '1px solid var(--border)',
      }}>
        {(['all', 'alerts'] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              flex: 1,
              padding: '7px 8px',
              fontSize: 12,
              fontWeight: tab === t ? 700 : 400,
              background: tab === t ? 'var(--bg-elevated)' : 'transparent',
              border: 'none',
              borderBottom: tab === t ? '2px solid var(--border-accent)' : '2px solid transparent',
              color: tab === t ? 'var(--text-primary)' : 'var(--text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 5,
            }}
          >
            {t === 'all' ? <Radio size={11} /> : <Bell size={11} />}
            {t === 'all' ? `All Feed (${allEvents.length})` : `Alerts (${alertEvents.length})`}
          </button>
        ))}
      </div>

      {/* ── Tab description ──────────────────────────────────────────── */}
      <div style={{ fontSize: 10, color: 'var(--text-muted)', padding: '4px 12px', borderBottom: '1px solid var(--border)' }}>
        {tab === 'all'
          ? 'All activity — normal, low, medium, high, critical + manual simulations'
          : 'High/critical alerts only · sorted by severity'}
      </div>

      {/* ── Event list ───────────────────────────────────────────────── */}
      <div className="panel-body" style={{ flex: 1, overflowY: 'auto' }}>
        {items.length === 0 && (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 12, marginTop: 40 }}>
            {tab === 'all' ? 'No feed events yet. Stream starts in ~10 s.' : 'No threshold alerts. All clear.'}
          </div>
        )}
        {items.map((a) => (
          <EventCard key={a.event_id + a.timestamp} event={a} selected={selectedAlertId === a.event_id} onClick={() => onAlertClick(a)} />
        ))}
      </div>
    </div>
  );
}
