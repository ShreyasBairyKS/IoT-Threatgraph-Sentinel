"""
routers/alerts.py - Alert endpoints.

  GET /alerts              ← all alerts, newest first
  GET /alerts/{event_id}   ← single alert by ID (for P4 drill-down)

Day 2+: serves from live AlertStore; mock fallback when store is empty.
"""

from fastapi import APIRouter, HTTPException
from backend.contracts import AlertEvent
from backend.store import alert_store
from backend.mocks.mock_store import MOCK_ALERTS

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertEvent])
async def get_alerts() -> list[AlertEvent]:
    """
    Return alerts newest-first from the live store.
    Polling fallback: call every 3s if WebSocket unavailable.
    Falls back to mock data when store is empty.
    """
    live = await alert_store.get_all()
    return live if live else MOCK_ALERTS


@router.get("/{event_id}", response_model=AlertEvent)
async def get_alert_by_id(event_id: str) -> AlertEvent:
    """
    Return a single alert by event_id — used by P4 drill-down panel.
    Checks live store first, then falls back to mock store.
    Returns 404 if not found in either.
    """
    # Check live store
    alert = await alert_store.get_by_id(event_id)
    if alert:
        return alert

    # Fallback: check mock store
    mock = next((a for a in MOCK_ALERTS if a.event_id == event_id), None)
    if mock:
        return mock

    raise HTTPException(status_code=404, detail=f"Alert '{event_id}' not found.")
