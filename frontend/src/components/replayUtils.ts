import type { ReplayFrame } from './ReplayTimeline';

export function buildReplayFrames(alerts: { timestamp: string; device_id: string }[]): ReplayFrame[] {
  return [...alerts]
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
    .map((a) => ({ timestamp: a.timestamp, label: a.device_id }));
}
