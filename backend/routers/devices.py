"""
routers/devices.py - GET /devices endpoint.

Day 2+: serves from live DeviceRegistry (populated via POST /ingest/anomaly).
Falls back to mock data when registry is empty so P4 is never blocked.
"""

from fastapi import APIRouter
from backend.contracts import DeviceSummary
from backend.store import device_registry
from backend.mocks.mock_store import MOCK_DEVICES

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=list[DeviceSummary])
async def get_devices() -> list[DeviceSummary]:
    """
    Return all known devices with their latest risk scores and status.
    Serves live data from DeviceRegistry; falls back to mock if empty.
    """
    live = await device_registry.get_all()
    return live if live else MOCK_DEVICES
