from __future__ import annotations

from fastapi import APIRouter, Query

from backend.contracts import AlertEvent
from backend.store import feed_store

router = APIRouter(prefix="/feed", tags=["feed"])


@router.get("", response_model=list[AlertEvent])
async def get_feed(limit: int = Query(default=200, ge=1, le=1000)) -> list[AlertEvent]:
    """Return all-severity event feed newest-first.

    This feed includes low/medium events and manual simulation events,
    unlike /alerts which intentionally remains thresholded for alerting semantics.
    """
    events = await feed_store.get_all()
    return events[:limit]
