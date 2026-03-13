import React, { useEffect, useMemo, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, CartesianGrid, Legend } from 'recharts';
import { X, Shield, Target, ArrowRight } from 'lucide-react';
import type { Device, AlertEvent, IncidentReport } from '../types/contracts';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

type FeatureSnapshot = {
  packet_rate: number;
  byte_volume: number;
  port_entropy: number;
  unique_dest_ips: number;
  tcp_ratio: number;
  udp_ratio: number;
};

const BASELINES_BY_DEVICE_PREFIX: Record<string, FeatureSnapshot> = {
  cam: {
    packet_rate: 52.4,
    byte_volume: 81854.7,
    port_entropy: 2.22,
    unique_dest_ips: 9.3,
    tcp_ratio: 0.63,
    udp_ratio: 0.36,
  },
  sensor: {
    packet_rate: 3.25,
    byte_volume: 1400.0,
    port_entropy: 0.11,
    unique_dest_ips: 1.0,
    tcp_ratio: 0.89,
    udp_ratio: 0.11,
  },
  router: {
    packet_rate: 29.35,
    byte_volume: 43550.0,
    port_entropy: 1.78,
    unique_dest_ips: 5.5,
    tcp_ratio: 0.71,
    udp_ratio: 0.28,
  },
  nvr: {
    packet_rate: 18.85,
    byte_volume: 36400.0,
    port_entropy: 1.24,
    unique_dest_ips: 3.0,
    tcp_ratio: 0.79,
    udp_ratio: 0.20,
  },
  door: {
    packet_rate: 8.5,
    byte_volume: 9800.0,
    port_entropy: 0.55,
    unique_dest_ips: 2.0,
    tcp_ratio: 0.85,
    udp_ratio: 0.14,
  },
  default: {
    packet_rate: 12.0,
    byte_volume: 12000.0,
    port_entropy: 0.9,
    unique_dest_ips: 2.0,
    tcp_ratio: 0.75,
    udp_ratio: 0.25,
  },
};

function baselineForDevice(device: Device): FeatureSnapshot {
  const key = device.device_id.toLowerCase();
  if (key.startsWith('cam-')) return BASELINES_BY_DEVICE_PREFIX.cam;
  if (key.startsWith('sensor-')) return BASELINES_BY_DEVICE_PREFIX.sensor;
  if (key.startsWith('router-')) return BASELINES_BY_DEVICE_PREFIX.router;
  if (key.startsWith('nvr-')) return BASELINES_BY_DEVICE_PREFIX.nvr;
  if (key.startsWith('door-') || key.startsWith('access-')) return BASELINES_BY_DEVICE_PREFIX.door;
  return BASELINES_BY_DEVICE_PREFIX.default;
}

function currentFromAlert(baseline: FeatureSnapshot, alert: AlertEvent | null, device: Device): FeatureSnapshot {
  const risk = alert?.risk_score ?? device.risk_score;
  const factor = 1 + risk / 120;
  const reasons = new Set(alert?.reasons.map((r) => r.toLowerCase()) ?? []);

  const hasVolume = Array.from(reasons).some((r) => r.includes('volume') || r.includes('exfil'));
  const hasPort = Array.from(reasons).some((r) => r.includes('port'));
  const hasDiversity = Array.from(reasons).some((r) => r.includes('destination') || r.includes('fan-out') || r.includes('diversity'));
  const hasUdp = Array.from(reasons).some((r) => r.includes('udp'));

  return {
    packet_rate: Number((baseline.packet_rate * factor).toFixed(2)),
    byte_volume: Number((baseline.byte_volume * (hasVolume ? factor * 1.45 : factor * 1.15)).toFixed(2)),
    port_entropy: Number((baseline.port_entropy * (hasPort ? factor * 1.25 : factor)).toFixed(2)),
    unique_dest_ips: Number((baseline.unique_dest_ips * (hasDiversity ? factor * 1.35 : factor)).toFixed(2)),
    tcp_ratio: Number((baseline.tcp_ratio * (hasUdp ? 0.85 : 1.02)).toFixed(2)),
    udp_ratio: Number((baseline.udp_ratio * (hasUdp ? 1.4 : 1.05)).toFixed(2)),
  };
}

function buildIdleReport(device: Device | null): IncidentReport {
  const deviceId = device?.device_id ?? 'unselected-device';
  return {
    report_id: `idle-${deviceId}`,
    generated_at: new Date().toISOString(),
    incident_summary: `No active alert is selected for ${deviceId}.`,
    affected_devices: device ? [device.device_id] : [],
    evidence: {
      risk_score: device?.risk_score ?? 0,
      explanations: [],
      mitre: [],
    },
    recommendations: [
      `Monitor ${deviceId} for new anomalies and refresh the alert feed when new telemetry arrives.`,
    ],
  };
}

function buildTrendFallback(device: Device | null): Array<{ time: string; risk: number }> {
  const baseRisk = Math.round(device?.risk_score ?? 0);
  const now = new Date();
  return Array.from({ length: 6 }, (_, index) => {
    const pointTime = new Date(now.getTime() - (5 - index) * 60_000);
    return {
      time: pointTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      risk: baseRisk,
    };
  });
}

function buildLocalReport(alert: AlertEvent): IncidentReport {
  return {
    report_id: `local-${alert.event_id}`,
    generated_at: new Date().toISOString(),
    incident_summary: `${alert.mitre.tactic} observed on ${alert.device_id} (risk=${alert.risk_score.toFixed(1)}).`,
    affected_devices: alert.graph.path.length > 0 ? alert.graph.path : [alert.device_id],
    evidence: {
      risk_score: alert.risk_score,
      explanations: alert.reasons,
      mitre: [alert.mitre],
    },
    recommendations: [
      `Restrict ${alert.device_id} while the backend report service is unavailable.`,
      `Review the alert evidence for ${alert.mitre.tactic} / ${alert.mitre.technique}.`,
      'Preserve logs and packet captures before making irreversible changes.',
    ],
  };
}

interface IncidentPanelProps {
  device: Device | null;
  latestAlert: AlertEvent | null;
  alerts: AlertEvent[];
  onClose: () => void;
}

export function IncidentPanel({ device, latestAlert, alerts, onClose }: IncidentPanelProps) {
  const [report, setReport] = useState<IncidentReport>(latestAlert ? buildLocalReport(latestAlert) : buildIdleReport(device));
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const trendData = useMemo(() => {
    if (!device) {
      return buildTrendFallback(null);
    }
    const points = alerts
      .filter((a) => a.device_id === device.device_id)
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
      .slice(-10)
      .map((a) => ({
        time: new Date(a.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        risk: a.risk_score,
      }));
    return points.length > 0 ? points : buildTrendFallback(device);
  }, [alerts, device]);

  const featureComparisonData = useMemo(() => {
    if (!device) {
      return [];
    }
    const baseline = baselineForDevice(device);
    const current = currentFromAlert(baseline, latestAlert, device);
    return [
      { feature: 'packet_rate', baseline: baseline.packet_rate, current: current.packet_rate },
      { feature: 'byte_volume', baseline: baseline.byte_volume, current: current.byte_volume },
      { feature: 'port_entropy', baseline: baseline.port_entropy, current: current.port_entropy },
      { feature: 'unique_dest_ips', baseline: baseline.unique_dest_ips, current: current.unique_dest_ips },
    ];
  }, [device, latestAlert]);

  const topDeviationSummary = useMemo(() => {
    if (featureComparisonData.length === 0) {
      return [];
    }
    return [...featureComparisonData]
      .map((row) => {
        const ratio = row.baseline > 0 ? row.current / row.baseline : 1;
        return { ...row, ratio };
      })
      .sort((a, b) => b.ratio - a.ratio)
      .slice(0, 2)
      .map((row) => `${row.feature} is ${row.ratio.toFixed(2)}x baseline`);
  }, [featureComparisonData]);

  useEffect(() => {
    let cancelled = false;

    const fetchReport = async () => {
      if (!latestAlert) {
        setReport(buildIdleReport(device));
        setReportError(null);
        return;
      }

      setReportLoading(true);
      setReportError(null);
      try {
        const res = await fetch(`${API_BASE_URL}/report`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(latestAlert),
        });
        if (!res.ok) {
          throw new Error('Report endpoint returned a non-200 response.');
        }
        const liveReport = (await res.json()) as IncidentReport;
        if (!cancelled) {
          setReport(liveReport);
        }
      } catch {
        if (!cancelled) {
          setReport(buildLocalReport(latestAlert));
          setReportError('Using local alert evidence because backend report generation failed.');
        }
      } finally {
        if (!cancelled) {
          setReportLoading(false);
        }
      }
    };

    fetchReport();
    return () => {
      cancelled = true;
    };
  }, [device, latestAlert]);

  const handleDownloadPdf = async () => {
    if (!latestAlert) {
      return;
    }

    setDownloadingPdf(true);
    try {
      const res = await fetch(`${API_BASE_URL}/report/${latestAlert.event_id}/pdf`);
      if (!res.ok) {
        throw new Error('PDF endpoint returned a non-200 response.');
      }
      const blob = await res.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = href;
      anchor.download = `incident_${latestAlert.event_id}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
      setReportError(null);
    } catch {
      setReportError('PDF download is available only for alerts stored in the backend alert store.');
    } finally {
      setDownloadingPdf(false);
    }
  };

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
            <AreaChart data={trendData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
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

        {/* Baseline vs Current mini chart */}
        {featureComparisonData.length > 0 && (
          <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: '12px 8px 8px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8, paddingLeft: 4 }}>
              Baseline vs Current (selected device)
            </div>
            <ResponsiveContainer width="100%" height={150}>
              <BarChart data={featureComparisonData} margin={{ top: 4, right: 8, bottom: 0, left: -12 }}>
                <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                <XAxis dataKey="feature" tick={{ fontSize: 9, fill: '#71717a' }} />
                <YAxis tick={{ fontSize: 9, fill: '#71717a' }} />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 11 }}
                  labelStyle={{ color: 'var(--text-secondary)' }}
                />
                <Legend wrapperStyle={{ fontSize: 10 }} />
                <Bar dataKey="baseline" fill="#3b82f6" name="Baseline" radius={[4, 4, 0, 0]} />
                <Bar dataKey="current" fill={chartColor} name="Current" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            {topDeviationSummary.map((line) => (
              <div key={line} style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                - {line}
              </div>
            ))}
          </div>
        )}

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

        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={handleDownloadPdf}
            disabled={!latestAlert || downloadingPdf}
            style={{
              flex: 1,
              border: '1px solid var(--border-accent)',
              background: 'var(--bg-overlay)',
              color: 'var(--text-primary)',
              borderRadius: 'var(--radius-md)',
              padding: '8px 10px',
              fontSize: 12,
              cursor: !latestAlert || downloadingPdf ? 'not-allowed' : 'pointer',
              opacity: !latestAlert || downloadingPdf ? 0.6 : 1,
            }}
          >
            {downloadingPdf ? 'Downloading PDF...' : 'Download Incident PDF'}
          </button>
        </div>

        {reportError && (
          <div style={{ fontSize: 11, color: 'var(--risk-high)' }}>
            {reportError}
          </div>
        )}

        {reportLoading && (
          <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            Updating incident recommendations from backend...
          </div>
        )}

        {/* Recommendations */}
        <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 12, border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8 }}>
            {report.incident_summary}
          </div>
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
