import React from 'react';
import { Monitor, Wifi, Server, Camera, Thermometer, Shield } from 'lucide-react';
import type { Device } from '../types/contracts';

// ── Helpers ──────────────────────────────────────────────────────────────
function getRiskClass(device: Device): string {
  if (device.status === 'critical') return 'critical';
  if (device.status === 'suspicious') return 'high';
  if (device.confidence === 'medium') return 'medium';
  if (device.confidence === 'low' && device.status !== 'normal') return 'low';
  return 'normal';
}

function getRiskColor(device: Device): string {
  const cls = getRiskClass(device);
  return `var(--risk-${cls})`;
}

const DEVICE_ICON: Record<string, React.ReactNode> = {
  camera:         <Camera size={14} />,
  router:         <Wifi size={14} />,
  nvr:            <Server size={14} />,
  sensor:         <Monitor size={14} />,
  access_control: <Shield size={14} />,
  thermostat:     <Thermometer size={14} />,
};

// ── Single device row ────────────────────────────────────────────────────
interface DeviceRowProps {
  device: Device;
  selected: boolean;
  onClick: () => void;
}

function DeviceRow({ device, selected, onClick }: DeviceRowProps) {
  const riskClass = getRiskClass(device);
  const riskColor = getRiskColor(device);

  return (
    <button
      onClick={onClick}
      style={{
        width: '100%',
        background: selected ? 'var(--bg-elevated)' : 'transparent',
        border: `1px solid ${selected ? 'var(--border-accent)' : 'var(--border)'}`,
        borderRadius: 'var(--radius-md)',
        padding: '10px 12px',
        cursor: 'pointer',
        textAlign: 'left',
        transition: 'all var(--transition)',
      }}
    >
      {/* Row header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--text-primary)', fontSize: 13, fontWeight: 500 }}>
          <span className={`pulse-dot ${device.status}`} />
          <span style={{ color: 'var(--text-secondary)' }}>
            {DEVICE_ICON[device.device_type] ?? <Monitor size={14} />}
          </span>
          <span className="truncate" style={{ maxWidth: 110 }}>{device.device_id}</span>
        </div>
        <span className={`badge badge-${riskClass}`}>{device.risk_score}</span>
      </div>

      {/* Risk bar */}
      <div className="risk-bar-wrap">
        <div
          className="risk-bar-fill"
          style={{ width: `${device.risk_score}%`, background: riskColor }}
        />
      </div>

      {/* Footer meta */}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, fontSize: 11, color: 'var(--text-secondary)' }}>
        <span>{device.device_type}</span>
        <span className={`badge badge-${device.confidence === 'high' ? 'high' : device.confidence === 'medium' ? 'medium' : 'low'}`} style={{ fontSize: 10, padding: '1px 6px' }}>
          {device.confidence}
        </span>
      </div>
    </button>
  );
}

// ── Component ────────────────────────────────────────────────────────────
interface DeviceListProps {
  devices: Device[];
  selectedId: string | null;
  onSelect: (device: Device) => void;
}

export function DeviceList({ devices, selectedId, onSelect }: DeviceListProps) {
  const alertingDevices = [...devices]
    .filter((device) => device.status !== 'normal')
    .sort((a, b) => b.risk_score - a.risk_score);
  const quietDevices = [...devices]
    .filter((device) => device.status === 'normal')
    .sort((a, b) => a.risk_score - b.risk_score);

  return (
    <div className="panel">
      <div className="card-header">
        <Monitor size={14} className="icon" />
        Devices
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-secondary)', fontWeight: 400 }}>
          {devices.length} online
        </span>
      </div>
      <div className="panel-body">
        <div style={{ fontSize: 11, color: 'var(--risk-high)', fontWeight: 600, marginBottom: 6 }}>
          Active Alerts ({alertingDevices.length})
        </div>
        {alertingDevices.map((d) => (
          <DeviceRow
            key={d.device_id}
            device={d}
            selected={selectedId === d.device_id}
            onClick={() => onSelect(d)}
          />
        ))}

        <div style={{ fontSize: 11, color: 'var(--risk-normal)', fontWeight: 600, marginTop: 10, marginBottom: 6 }}>
          No Active Alerts ({quietDevices.length})
        </div>
        {quietDevices.length === 0 && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
            All monitored devices are currently participating in an active incident path.
          </div>
        )}
        {quietDevices.map((d) => (
          <DeviceRow
            key={d.device_id}
            device={d}
            selected={selectedId === d.device_id}
            onClick={() => onSelect(d)}
          />
        ))}
      </div>
    </div>
  );
}
