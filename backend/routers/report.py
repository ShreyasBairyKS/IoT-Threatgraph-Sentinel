"""
routers/report.py - POST /report endpoint.

Accepts an alert event, generates an incident report JSON.
Day 1: returns mock report (stub). Day 3: wires generate_report.py
and export_pdf.py to produce real reports from live alert data.
"""

from fastapi import APIRouter, Body
from backend.contracts import AlertEvent, IncidentReport
from backend.mocks.mock_store import MOCK_REPORT

router = APIRouter(prefix="/report", tags=["report"])


@router.post("", response_model=IncidentReport)
async def generate_report(alert: AlertEvent = Body(...)) -> IncidentReport:
    """
    Generate an incident report from an alert event.

    Day 1 behaviour: ignores the payload and returns the mock report.
    Day 3 behaviour: passes alert through generate_report.py pipeline
    and invokes the PDF export path.

    Body should be a fully formed AlertEvent payload.
    """
    # TODO (Day 3): replace with real report generation
    # from backend.reporting.generate_report import build_report
    # return await build_report(alert)
    return MOCK_REPORT
