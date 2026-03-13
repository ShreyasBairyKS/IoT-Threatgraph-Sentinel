"""
routers/devices.py - GET /devices endpoint.

Returns the list of known IoT devices and their current risk status.
Day 1: returns mock data. Day 3: wires to real P1/P2 scoring outputs.
"""

from fastapi import APIRouter
from backend.contracts import DeviceSummary
from backend.mocks.mock_store import MOCK_DEVICES

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=list[DeviceSummary])
async def get_devices() -> list[DeviceSummary]:
    """
    Return all known devices with their latest risk scores and status.
    """
    return MOCK_DEVICES
