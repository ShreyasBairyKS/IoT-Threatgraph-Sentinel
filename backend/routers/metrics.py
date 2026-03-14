from fastapi import APIRouter

from backend.store import processing_stats

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/summary")
async def get_processing_summary() -> dict[str, int]:
    """Return telemetry processing counters for the frontend summary strip."""
    return await processing_stats.snapshot()