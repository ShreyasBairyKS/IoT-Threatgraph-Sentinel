"""
routers/alerts.py - GET /alerts endpoint.

Returns the current list of alert events.
Day 1: returns mock data. Day 3: wires to real in-memory alert store
populated by P1/P2 ingestion pipeline.
"""

from fastapi import APIRouter
from backend.contracts import AlertEvent
from backend.mocks.mock_store import MOCK_ALERTS

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertEvent])
async def get_alerts() -> list[AlertEvent]:
    """
    Return all current alerts ordered by most recent.
    Polling fallback: clients that cannot use WebSocket should call
    this endpoint every 3 seconds (see docs/ARCHITECTURE.md Section 9).
    """
    return MOCK_ALERTS
