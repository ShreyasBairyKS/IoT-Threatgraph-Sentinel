"""
reporting/export_pdf.py - PDF export from IncidentReport using ReportLab.

Generates a styled PDF with:
  - Header banner (report ID, timestamp, severity colour)
  - Incident summary paragraph
  - Evidence table (risk score, confidence, MITRE)
  - Attack path section
  - Recommendations list

Target: < 5 seconds generation time (see docs/ARCHITECTURE.md Section 8).
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)

from backend.contracts import IncidentReport

# ── Colour palette ──────────────────────────────────────────────────────────
BRAND_DARK   = colors.HexColor("#0D1B2A")   # deep navy
BRAND_ACCENT = colors.HexColor("#E63946")   # alert red
BRAND_LIGHT  = colors.HexColor("#F1FAEE")   # off-white background row
BRAND_TEXT   = colors.HexColor("#1D3557")   # dark blue text
GREY         = colors.HexColor("#8D99AE")
WHITE        = colors.white


def export_pdf(report: IncidentReport) -> bytes:
    """
    Render an IncidentReport to PDF bytes using ReportLab.

    Returns:
        bytes: Raw PDF binary content ready for HTTP response.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Incident Report {report.report_id}",
        author="IoT ThreatGraph Sentinel — P3",
    )

    styles = getSampleStyleSheet()
    story: list = []

    # ── 1. Header banner ────────────────────────────────────────────────────
    header_style = ParagraphStyle(
        "Header",
        parent=styles["Title"],
        fontSize=18,
        textColor=WHITE,
        backColor=BRAND_DARK,
        spaceAfter=0,
        alignment=TA_CENTER,
        borderPad=10,
    )
    story.append(Paragraph("🛡 IoT ThreatGraph Sentinel", header_style))
    story.append(Paragraph("Incident Report", header_style))
    story.append(Spacer(1, 0.4 * cm))

    # ── 2. Meta table (report ID / timestamp) ───────────────────────────────
    generated = report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_data = [
        ["Report ID", report.report_id],
        ["Generated",  generated],
        ["Affected Devices", ", ".join(report.affected_devices)],
    ]
    meta_table = Table(meta_data, colWidths=[4 * cm, 13 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), BRAND_DARK),
        ("TEXTCOLOR",  (0, 0), (0, -1), WHITE),
        ("BACKGROUND", (1, 0), (1, -1), BRAND_LIGHT),
        ("TEXTCOLOR",  (1, 0), (1, -1), BRAND_TEXT),
        ("FONTNAME",   (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.4, GREY),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [BRAND_LIGHT, WHITE]),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── 3. Incident Summary ─────────────────────────────────────────────────
    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        textColor=BRAND_ACCENT,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        textColor=BRAND_TEXT,
        fontSize=10,
        leading=14,
    )

    story.append(Paragraph("Incident Summary", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(report.incident_summary, body_style))
    story.append(Spacer(1, 0.4 * cm))

    # ── 4. Evidence ─────────────────────────────────────────────────────────
    story.append(Paragraph("Evidence", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.2 * cm))

    ev = report.evidence
    mitre_str = "; ".join(
        f"{m.tactic} ({m.technique})" for m in ev.mitre
    )
    evidence_data = [
        ["Field", "Value"],
        ["Risk Score", f"{ev.risk_score:.1f} / 100"],
        ["MITRE Tactics", mitre_str or "N/A"],
    ]
    for i, expl in enumerate(ev.explanations, 1):
        evidence_data.append([f"Finding {i}", expl])

    ev_table = Table(evidence_data, colWidths=[4 * cm, 13 * cm])
    ev_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND",    (0, 0), (0, -1), BRAND_DARK),
        ("TEXTCOLOR",     (0, 0), (0, -1), WHITE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [BRAND_LIGHT, WHITE]),
        ("TEXTCOLOR",     (1, 1), (-1, -1), BRAND_TEXT),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("GRID",          (0, 0), (-1, -1), 0.4, GREY),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 0.4 * cm))

    # ── 5. Recommendations ──────────────────────────────────────────────────
    story.append(Paragraph("Recommendations", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.2 * cm))

    bullet_style = ParagraphStyle(
        "Bullet",
        parent=body_style,
        leftIndent=14,
        bulletIndent=4,
        spaceAfter=4,
    )
    for rec in report.recommendations:
        story.append(Paragraph(f"• {rec}", bullet_style))

    story.append(Spacer(1, 0.6 * cm))

    # ── 6. Footer ───────────────────────────────────────────────────────────
    footer_style = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=7,
        textColor=GREY,
        alignment=TA_CENTER,
    )
    story.append(HRFlowable(width="100%", thickness=0.4, color=GREY))
    story.append(Spacer(1, 0.1 * cm))
    story.append(Paragraph(
        f"Generated by IoT ThreatGraph Sentinel · {generated} · Confidential",
        footer_style,
    ))

    doc.build(story)
    return buffer.getvalue()

