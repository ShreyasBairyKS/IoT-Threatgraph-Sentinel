"""
routers/alerts.py - Alert endpoints.

  GET /alerts              ← all alerts, newest first
  GET /alerts/{event_id}   ← single alert by ID (for P4 drill-down)

Day 2+: serves from live AlertStore only.
"""

from fastapi import APIRouter, HTTPException
from backend.contracts import AlertEvent
from backend.store import alert_store, alert_context_store

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertEvent])
async def get_alerts() -> list[AlertEvent]:
    """
    Return alerts newest-first from the live store.
    Polling fallback: call every 3s if WebSocket unavailable.
    """
    return await alert_store.get_all()


@router.get("/{event_id}", response_model=AlertEvent)
async def get_alert_by_id(event_id: str) -> AlertEvent:
    """
    Return a single alert by event_id — used by P4 drill-down panel.
    Returns 404 when the event is not present in the live store.
    """
    alert = await alert_store.get_by_id(event_id)
    if alert:
        return alert

    raise HTTPException(status_code=404, detail=f"Alert '{event_id}' not found.")


@router.get("/{event_id}/context")
async def get_alert_context(event_id: str) -> dict[str, object]:
    """
    Return frozen graph + device snapshot for the given alert event_id.
    This enables frontend drill-down to reproduce historical graph context.
    """
    context = await alert_context_store.get(event_id)
    if context is None:
        raise HTTPException(status_code=404, detail=f"Context for alert '{event_id}' not found.")

    devices = context.get("devices", [])
    enrichment = context.get("enrichment")

    return {
        "devices": [d.model_dump(mode="json") for d in devices],
        "enrichment": enrichment.model_dump(mode="json") if enrichment else None,
    }
