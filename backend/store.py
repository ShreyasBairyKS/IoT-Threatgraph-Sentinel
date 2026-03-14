"""
store.py - In-memory alert and device state store.

Replaces the static mock_store on Day 2+.

Architecture:
  - AlertStore holds up to MAX_ALERT_STORE recent alerts.
  - on add_alert() it also triggers a WebSocket broadcast instantly.
  - DeviceRegistry maintains latest DeviceSummary per device_id.
  - GraphStore holds the latest GraphEnrichment snapshot.

Day 3: P1 calls add_anomaly_result(), P2 calls add_graph_enrichment().
The store auto-merges and emits an AlertEvent on threshold breach.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from backend.config import settings
from backend.contracts import (
    AlertEvent,
    AlertGraph,
    AnomalyResult,
    DeviceSummary,
    GraphEnrichment,
    MITRETag,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Risk threshold: anomaly results at or above this become AlertEvents
# ---------------------------------------------------------------------------
ALERT_RISK_THRESHOLD = settings.ALERT_RISK_THRESHOLD

# Severity bands
def _risk_to_severity(score: float) -> str:
    if score >= settings.SEVERITY_CRITICAL_THRESHOLD:
        return "critical"
    if score >= settings.SEVERITY_HIGH_THRESHOLD:
        return "high"
    if score >= settings.SEVERITY_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


class AlertStore:
    """Thread-safe in-memory deque for recent AlertEvents."""

    def __init__(self, maxlen: int = settings.MAX_ALERT_STORE) -> None:
        self._alerts: deque[AlertEvent] = deque(maxlen=maxlen)
        self._lock = asyncio.Lock()

    async def add(self, alert: AlertEvent) -> None:
        async with self._lock:
            self._alerts.appendleft(alert)  # newest first
        logger.info("Alert stored: %s  risk=%.1f", alert.event_id, alert.risk_score)

    async def get_all(self) -> list[AlertEvent]:
        async with self._lock:
            return list(self._alerts)

    async def get_by_id(self, event_id: str) -> Optional[AlertEvent]:
        async with self._lock:
            return next((a for a in self._alerts if a.event_id == event_id), None)


class DeviceRegistry:
    """Latest DeviceSummary keyed by device_id."""

    def __init__(self) -> None:
        self._devices: dict[str, DeviceSummary] = {}
        self._lock = asyncio.Lock()

    async def upsert(self, device: DeviceSummary) -> None:
        async with self._lock:
            self._devices[device.device_id] = device

    async def get_all(self) -> list[DeviceSummary]:
        async with self._lock:
            return list(self._devices.values())


class GraphStore:
    """Latest GraphEnrichment snapshot."""

    def __init__(self) -> None:
        self._snapshot: Optional[GraphEnrichment] = None
        self._lock = asyncio.Lock()

    async def update(self, enrichment: GraphEnrichment) -> None:
        async with self._lock:
            self._snapshot = enrichment

    async def get(self) -> Optional[GraphEnrichment]:
        async with self._lock:
            return self._snapshot


class AlertContextStore:
    """Stores per-alert graph + device snapshot context for later drill-down."""

    def __init__(self) -> None:
        self._contexts: dict[str, dict[str, object]] = {}
        self._lock = asyncio.Lock()

    async def save(
        self,
        event_id: str,
        devices: list[DeviceSummary],
        enrichment: Optional[GraphEnrichment],
    ) -> None:
        async with self._lock:
            self._contexts[event_id] = {
                "devices": devices,
                "enrichment": enrichment,
            }

    async def get(self, event_id: str) -> Optional[dict[str, object]]:
        async with self._lock:
            return self._contexts.get(event_id)


class ProcessingStats:
    """Tracks how many telemetry items were processed and how many raised alerts."""

    def __init__(self) -> None:
        self._total_submissions = 0
        self._alert_submissions = 0
        self._non_alert_submissions = 0
        self._lock = asyncio.Lock()

    async def record(self, generated_alert: bool) -> None:
        async with self._lock:
            self._total_submissions += 1
            if generated_alert:
                self._alert_submissions += 1
            else:
                self._non_alert_submissions += 1

    async def snapshot(self) -> dict[str, int]:
        async with self._lock:
            return {
                "total_submissions": self._total_submissions,
                "alert_submissions": self._alert_submissions,
                "non_alert_submissions": self._non_alert_submissions,
            }


# ---------------------------------------------------------------------------
# Merge helper: AnomalyResult + GraphEnrichment → AlertEvent
# ---------------------------------------------------------------------------

def build_alert_event(
    anomaly: AnomalyResult,
    graph: Optional[GraphEnrichment] = None,
) -> AlertEvent:
    """
    Combine P1 AnomalyResult and (optional) P2 GraphEnrichment into
    a contract-compliant AlertEvent for WebSocket broadcast.
    """
    mitre = graph.mitre if graph else MITRETag(tactic="Unknown", technique="T0000")
    path = graph.attack_paths[0] if graph and graph.attack_paths else [anomaly.device_id]
    next_targets = [p.device_id for p in graph.next_target_prediction] if graph else []

    return AlertEvent(
        event_id=f"evt_{uuid.uuid4().hex[:6]}",
        timestamp=datetime.now(tz=timezone.utc),
        severity=_risk_to_severity(anomaly.scores.final_risk),
        device_id=anomaly.device_id,
        device_type=anomaly.device_type,
        risk_score=anomaly.scores.final_risk,
        confidence=anomaly.scores.confidence,
        reasons=anomaly.explanations,
        mitre=mitre,
        graph=AlertGraph(path=path, next_targets=next_targets),
    )


# ---------------------------------------------------------------------------
# Singletons — import these everywhere
# ---------------------------------------------------------------------------

alert_store = AlertStore()
device_registry = DeviceRegistry()
graph_store = GraphStore()
processing_stats = ProcessingStats()
alert_context_store = AlertContextStore()
