"""
routers/alerts.py - GET /alerts endpoint.

Day 2+: serves from live AlertStore (populated via POST /ingest/anomaly).
Falls back to mock data when store is empty so P4 is never blocked.
"""

from fastapi import APIRouter
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
