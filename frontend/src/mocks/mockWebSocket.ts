// ==========================================================================
// IoT ThreatGraph Sentinel — Mock WebSocket (Day 1)
// Simulates the P3 WebSocket broadcast of alert.created events.
// Replace with `new WebSocket('ws://localhost:8000/ws/alerts')` on Day 3.
// ==========================================================================

import { MOCK_ALERTS } from './mockData';
import type { AlertEvent } from '../types/contracts';

type AlertHandler = (event: AlertEvent) => void;

export class MockWebSocket {
  private handlers: AlertHandler[] = [];
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private index = 0;

  /** Register a callback for incoming alert events */
  onAlert(handler: AlertHandler): void {
    this.handlers.push(handler);
  }

  /** Start streaming mock alerts (defaults to one alert per 4 seconds) */
  connect(intervalMs = 4000): void {
    this.index = 0;
    // Emit the first alert immediately
    this.dispatch();
    this.intervalId = setInterval(() => this.dispatch(), intervalMs);
  }

  private dispatch(): void {
    if (MOCK_ALERTS.length === 0) return;
    const alert = MOCK_ALERTS[this.index % MOCK_ALERTS.length];
    this.index++;
    this.handlers.forEach((h) => h(alert));
  }

  disconnect(): void {
    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }
}
