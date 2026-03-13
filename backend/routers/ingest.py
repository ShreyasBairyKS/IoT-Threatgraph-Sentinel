"""
routers/ingest.py - Internal ingestion endpoints for P1 and P2.

These are the integration seams that P1 and P2 POST into on Day 3/4.

  POST /ingest/anomaly   ← P1 (AnomalyResult)
  POST /ingest/graph     ← P2 (GraphEnrichment)

When an AnomalyResult above the risk threshold arrives:
  1. Build an AlertEvent (merging latest GraphEnrichment if available).
  2. Save to AlertStore.
  3. Upsert DeviceRegistry.
  4. Broadcast over WebSocket to all P4 clients.

This means P4 gets real-time updates the moment P1/P2 push data —
no polling, no manual wiring needed on integration day.
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, BackgroundTasks

from backend.contracts import AnomalyResult, GraphEnrichment, DeviceSummary
from backend.store import (
    alert_store,
    device_registry,
    graph_store,
    build_alert_event,
    ALERT_RISK_THRESHOLD,
)
from backend.ws.broadcaster import manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])


# ---------------------------------------------------------------------------
# P1 → P3: Anomaly result ingestion
# ---------------------------------------------------------------------------

@router.post("/anomaly", status_code=202)
async def ingest_anomaly(
    result: AnomalyResult,
    background_tasks: BackgroundTasks,
) -> dict[str, str]:
    """
    Receive an AnomalyResult from the P1 ml-worker.

    - If risk >= threshold → builds AlertEvent, stores it, broadcasts over WS.
    - Always upserts the DeviceRegistry with latest risk / status.

    Returns 202 Accepted immediately; processing happens in background.
    """
    background_tasks.add_task(_process_anomaly, result)
    return {"status": "accepted", "device_id": result.device_id}


async def _process_anomaly(result: AnomalyResult) -> None:
    from datetime import datetime, timezone

    # 1. Update device registry
    from backend.store import _risk_to_severity
    status = _risk_to_severity(result.scores.final_risk)
    status_map = {"critical": "critical", "high": "critical", "medium": "suspicious", "low": "normal"}
    device = DeviceSummary(
        device_id=result.device_id,
        device_type=result.device_type,
        last_seen=datetime.now(tz=timezone.utc),
        risk_score=result.scores.final_risk,
        confidence=result.scores.confidence,
        status=status_map.get(status, "normal"),
    )
    await device_registry.upsert(device)
    logger.info("Device registry updated: %s  risk=%.1f", result.device_id, result.scores.final_risk)

    # 2. Only create an alert if above threshold
    if result.scores.final_risk < ALERT_RISK_THRESHOLD:
        logger.info("Risk %.1f below threshold %.1f — no alert.", result.scores.final_risk, ALERT_RISK_THRESHOLD)
        return

    # 3. Merge latest graph enrichment (may be None on early days)
    graph = await graph_store.get()
    alert = build_alert_event(result, graph)

    # 4. Store + broadcast
    await alert_store.add(alert)
    await manager.broadcast(alert.model_dump(mode="json"))
    logger.info("Alert broadcast: %s  severity=%s", alert.event_id, alert.severity)


# ---------------------------------------------------------------------------
# P2 → P3: Graph enrichment ingestion
# ---------------------------------------------------------------------------

@router.post("/graph", status_code=202)
async def ingest_graph(enrichment: GraphEnrichment) -> dict[str, str]:
    """
    Receive a GraphEnrichment snapshot from the P2 graph-worker.

    Updates the graph store so subsequent anomaly results are enriched
    with the latest propagation risk, attack paths, and MITRE tags.

    Returns 202 Accepted.
    """
    await graph_store.update(enrichment)
    logger.info(
        "Graph store updated: source=%s  prop_risk=%.2f",
        enrichment.source_device,
        enrichment.propagation_risk,
    )
    return {"status": "accepted", "source_device": enrichment.source_device}
