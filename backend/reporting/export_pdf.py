"""
reporting/export_pdf.py - PDF export from IncidentReport.

Day 1: stub only — interface defined and placeholder implemented.
Day 3: replace with real PDF rendering via ReportLab or WeasyPrint.

Target: PDF generated in < 5 seconds (see docs/ARCHITECTURE.md Section 8).
"""

from __future__ import annotations

import io
from backend.contracts import IncidentReport


def export_pdf(report: IncidentReport) -> bytes:
    """
    Render an IncidentReport to PDF bytes.

    Day 1 stub: returns a minimal plain-text PDF shell so the endpoint
    does not crash. Day 3: replace with styled PDF using ReportLab.

    Returns:
        bytes: Raw PDF binary content.
    """
    # TODO (Day 3): implement full PDF rendering
    # Example with ReportLab:
    #
    # from reportlab.lib.pagesizes import letter
    # from reportlab.pdfgen import canvas
    #
    # buffer = io.BytesIO()
    # c = canvas.Canvas(buffer, pagesize=letter)
    # c.drawString(72, 750, f"Incident Report: {report.report_id}")
    # c.drawString(72, 730, report.incident_summary)
    # ...
    # c.save()
    # return buffer.getvalue()

    # Day 1 placeholder: minimal valid PDF binary
    lines = [
        f"%PDF-1.4 stub",
        f"Report ID: {report.report_id}",
        f"Generated: {report.generated_at}",
        f"Summary: {report.incident_summary}",
        f"Affected: {', '.join(report.affected_devices)}",
        f"Risk Score: {report.evidence.risk_score}",
    ]
    return "\n".join(lines).encode("utf-8")
