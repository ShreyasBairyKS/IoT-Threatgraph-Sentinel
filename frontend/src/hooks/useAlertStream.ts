// ==========================================================================
// IoT ThreatGraph Sentinel — useAlertStream (Day 3)
// Tries a real WebSocket to P3 backend first.
// Falls back to MockWebSocket automatically if the backend is unavailable
// (expected behaviour while feature branches haven't been merged yet).
//
// Downstream callers: App.tsx
// P3 integration point: ws://localhost:8000/ws/alerts  (alert.created events)
// ==========================================================================

import { useCallback, useEffect, useRef, useState } from 'react';
import { MockWebSocket } from '../mocks/mockWebSocket';
import { MOCK_ALERTS } from '../mocks/mockData';
import type { AlertEvent } from '../types/contracts';

export type WsStatus = 'connecting' | 'live' | 'mock' | 'error';

const WS_URL = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000/ws/alerts';
/** If the real WS doesn't open within this many ms, fall back to mock. */
const CONNECT_TIMEOUT_MS = 2000;
/** Max alerts to keep in memory. */
const MAX_ALERTS = 50;

export interface AlertStreamState {
  alerts: AlertEvent[];
  wsStatus: WsStatus;
  /** Force a switchover to mock mode (useful for offline dev). */
  useMock: () => void;
}

function normalizeAlertEvent(data: Partial<AlertEvent>): AlertEvent | null {
  if (data.event_type !== 'alert.created') return null;
  if (!data.device_id || !data.event_id) return null;

  return {
    event_type: 'alert.created',
    event_id: data.event_id,
    timestamp: data.timestamp ?? new Date().toISOString(),
    severity: data.severity ?? 'low',
    device_id: data.device_id,
    device_type: data.device_type ?? 'unknown',
    risk_score: typeof data.risk_score === 'number' ? data.risk_score : 0,
    confidence: data.confidence ?? 'low',
    reasons: Array.isArray(data.reasons) ? data.reasons : [],
    mitre: {
      tactic: data.mitre?.tactic ?? 'Unknown',
      technique: data.mitre?.technique ?? 'T0000',
    },
    graph: {
      path: Array.isArray(data.graph?.path) ? data.graph.path : [],
      next_targets: Array.isArray(data.graph?.next_targets) ? data.graph.next_targets : [],
    },
  };
}

export function useAlertStream(): AlertStreamState {
  const [alerts, setAlerts] = useState<AlertEvent[]>(MOCK_ALERTS);
  const [wsStatus, setWsStatus] = useState<WsStatus>('connecting');

  // Refs so callbacks always close over latest values
  const wsRef = useRef<WebSocket | null>(null);
  const mockRef = useRef<MockWebSocket | null>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isMockMode = useRef(false);

  const appendAlert = useCallback((evt: AlertEvent) => {
    setAlerts((prev) => {
      // Deduplicate by event_id + timestamp
      if (prev.some((a) => a.event_id === evt.event_id && a.timestamp === evt.timestamp)) {
        const unique: AlertEvent = {
          ...evt,
          event_id: `${evt.event_id}_${Date.now()}`,
          timestamp: new Date().toISOString(),
        };
        return [unique, ...prev].slice(0, MAX_ALERTS);
      }
      return [evt, ...prev].slice(0, MAX_ALERTS);
    });
  }, []);

  // ── Mock fallback ──────────────────────────────────────────────────────────
  const startMock = useCallback(() => {
    if (isMockMode.current) return;
    isMockMode.current = true;
    setWsStatus('mock');

    const mock = new MockWebSocket();
    mockRef.current = mock;
    mock.onAlert(appendAlert);
    mock.connect(5000);                // new alert every 5 s
  }, [appendAlert]);

  // ── Real WebSocket attempt ─────────────────────────────────────────────────
  const startLive = useCallback(() => {
    let ws: WebSocket;
    try {
      ws = new WebSocket(WS_URL);
    } catch {
      // ws:// scheme blocked (e.g. file:// context) → go mock immediately
      startMock();
      return;
    }

    wsRef.current = ws;

    // Fallback timer — if not open in CONNECT_TIMEOUT_MS, switch to mock
    timeoutRef.current = setTimeout(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        ws.close();
        startMock();
      }
    }, CONNECT_TIMEOUT_MS);

    ws.onopen = () => {
      if (timeoutRef.current) { clearTimeout(timeoutRef.current); timeoutRef.current = null; }
      isMockMode.current = false;
      setWsStatus('live');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data as string) as Partial<AlertEvent>;
        const normalized = normalizeAlertEvent(data);
        if (normalized) appendAlert(normalized);
      } catch {
        // Ignore malformed frames
      }
    };

    ws.onerror = () => {
      setWsStatus('error');
    };

    ws.onclose = () => {
      // If we were live and the socket drops, switch to mock as graceful fallback
      if (!isMockMode.current) {
        startMock();
      }
    };
  }, [startMock, appendAlert]);

  // ── Lifecycle ──────────────────────────────────────────────────────────────
  useEffect(() => {
    startLive();

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      if (wsRef.current) wsRef.current.close();
      if (mockRef.current) mockRef.current.disconnect();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { alerts, wsStatus, useMock: startMock };
}
