"""
reporting/generate_report.py - Incident report generator.

Day 1: stub only — structure and interface defined for P4 type safety.
Day 3: replace body with real logic consuming live AlertEvent + GraphEnrichment.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from backend.contracts import (
    AlertEvent,
    IncidentEvidence,
    IncidentReport,
    MITRETag,
)


def build_report(alert: AlertEvent) -> IncidentReport:
    """
    Generate an IncidentReport from an AlertEvent.

    Day 1 stub: constructs a report directly from the alert payload.
    Day 3: enrich with device history, graph propagation paths, and
    P1 SHAP explanations pulled from the ingestion store.
    """
    mitre_tags: list[MITRETag] = [alert.mitre]

    evidence = IncidentEvidence(
        risk_score=alert.risk_score,
        explanations=alert.reasons,
        mitre=mitre_tags,
    )

    affected_devices = [alert.device_id] + alert.graph.path[1:]

    recommendations = _generate_recommendations(alert)

    return IncidentReport(
        report_id=f"rep_{uuid.uuid4().hex[:6]}",
        generated_at=datetime.now(tz=timezone.utc),
        incident_summary=(
            f"Potential {alert.mitre.tactic} initiated from {alert.device_id}"
        ),
        affected_devices=list(dict.fromkeys(affected_devices)),  # deduplicate, preserve order
        evidence=evidence,
        recommendations=recommendations,
    )


def _generate_recommendations(alert: AlertEvent) -> list[str]:
    """
    Rule-based recommendation strings for the report.
    Day 3: extend with MITRE-sourced mitigation text and P2 path severity.
    """
    recs: list[str] = []

    if alert.risk_score >= 75:
        recs.append(f"Isolate {alert.device_id} into quarantine VLAN immediately.")

    recs.append(
        f"Block outbound connections from {alert.device_id} to unknown external endpoints."
    )

    if alert.graph.next_targets:
        targets = ", ".join(alert.graph.next_targets)
        recs.append(f"Monitor {targets} closely — identified as next likely propagation targets.")

    recs.append(
        f"Run firmware integrity check on all devices in path: "
        f"{' → '.join(alert.graph.path)}."
    )

    return recs
