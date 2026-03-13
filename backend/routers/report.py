"""
routers/report.py - Report generation endpoints.

  POST /report            ← accepts AlertEvent, returns IncidentReport JSON
  GET  /report/{event_id}/pdf  ← returns downloadable PDF for a stored alert

Day 2: generate_report.py is wired; PDF stub returns bytes.
Day 5: PDF upgraded to styled ReportLab output.
"""

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import Response

from backend.contracts import AlertEvent, IncidentReport
from backend.store import alert_store
from backend.mocks.mock_store import MOCK_ALERTS
from backend.reporting.generate_report import build_report
from backend.reporting.export_pdf import export_pdf

router = APIRouter(prefix="/report", tags=["report"])


@router.post("", response_model=IncidentReport)
async def generate_report(alert: AlertEvent = Body(...)) -> IncidentReport:
    """
    Generate an IncidentReport from an AlertEvent payload.
    Uses the real build_report() pipeline (rule-based recommendations + MITRE merge).
    """
    return build_report(alert)


@router.get("/{event_id}/pdf")
async def download_pdf(event_id: str) -> Response:
    """
    Generate and download a PDF for a previously stored alert event.

    Looks up the alert in AlertStore by event_id, builds the report,
    exports to PDF bytes, returns as application/pdf attachment.
    """
    alert = await alert_store.get_by_id(event_id)
    if alert is None:
        # Dev fallback: allow PDF generation for baseline mock alerts.
        alert = next((a for a in MOCK_ALERTS if a.event_id == event_id), None)

    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{event_id}' not found in store.")

    report = build_report(alert)
    pdf_bytes = export_pdf(report)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{report.report_id}.pdf"},
    )

