"""
reporting/generate_report.py - Incident report generator.

Builds a full IncidentReport from an AlertEvent using:
  - Live risk score and alert explanations
  - MITRE ATT&CK tactic-driven mitigation recommendations
  - Graph propagation path analysis
  - Severity-tiered response actions
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

# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic → recommended mitigation actions
# ---------------------------------------------------------------------------
_MITRE_MITIGATIONS: dict[str, list[str]] = {
    "Lateral Movement": [
        "Enforce network segmentation with micro-perimeters between device zones.",
        "Deploy east-west traffic inspection on internal VLANs.",
        "Review and revoke unnecessary inter-device trust relationships.",
    ],
    "Command and Control": [
        "Block all outbound connections to untrusted external IPs at the perimeter firewall.",
        "Inspect DNS responses for C2 beaconing patterns (DGA, high-TTL abuse).",
        "Enable deep packet inspection for IoT protocol (MQTT, CoAP) anomalies.",
    ],
    "Exfiltration": [
        "Apply egress filtering rules to restrict large or unusual outbound data transfers.",
        "Enable data loss prevention (DLP) policies on network chokepoints.",
        "Review RTSP / media-stream destinations and allowlist legitimate endpoints.",
    ],
    "Discovery": [
        "Disable unnecessary device-discovery protocols (UPnP, mDNS) across IoT segments.",
        "Alert on port-scan patterns originating from IoT devices.",
        "Implement honeypot devices to detect internal reconnaissance.",
    ],
    "Impact": [
        "Preserve forensic evidence before any device restart or reset.",
        "Investigate logs for signs of firmware tampering or factory-reset attempts.",
    ],
    "Persistence": [
        "Audit startup configurations and scheduled tasks on affected devices.",
        "Force firmware re-flash from a verified golden image.",
    ],
    "Privilege Escalation": [
        "Rotate credentials and API keys for all devices within the blast radius.",
        "Enforce the principle of least privilege on device management interfaces.",
    ],
    "Defense Evasion": [
        "Review audit log integrity — check for gaps or deletions.",
        "Enable tamper-evident logging forwarded to an off-device SIEM.",
    ],
    "Credential Access": [
        "Immediately rotate all credentials associated with affected devices.",
        "Enable multi-factor authentication on device management portals.",
    ],
    "Initial Access": [
        "Review all internet-facing device ports and close unnecessary service endpoints.",
        "Ensure device firmware is patched to the latest vendor release.",
    ],
}

_DEFAULT_MITIGATIONS = [
    "Consult the MITRE ATT&CK for ICS framework for device-type-specific mitigations.",
]


def build_report(alert: AlertEvent) -> IncidentReport:
    """
    Generate a full IncidentReport from an AlertEvent.

    Combines:
      - Risk score and model explanations from the alert
      - MITRE ATT&CK tactic-driven mitigation recommendations
      - Propagation path severity analysis from the graph enrichment
    """
    mitre_tags: list[MITRETag] = [alert.mitre]

    evidence = IncidentEvidence(
        risk_score=alert.risk_score,
        explanations=alert.reasons,
        mitre=mitre_tags,
    )

    # Deduplicate path devices (keep order: compromised first, then propagation chain)
    affected_devices = list(dict.fromkeys([alert.device_id] + alert.graph.path[1:]))

    recommendations = _generate_recommendations(alert)

    severity_label = (
        "CRITICAL" if alert.risk_score >= 85
        else "HIGH" if alert.risk_score >= 70
        else "MEDIUM" if alert.risk_score >= 50
        else "LOW"
    )

    return IncidentReport(
        report_id=f"rep_{uuid.uuid4().hex[:6]}",
        generated_at=datetime.now(tz=timezone.utc),
        incident_summary=(
            f"[{severity_label}] {alert.mitre.tactic} detected on {alert.device_id} "
            f"(risk={alert.risk_score:.1f}, technique={alert.mitre.technique}). "
            f"Attack path spans {len(affected_devices)} device(s)."
        ),
        affected_devices=affected_devices,
        evidence=evidence,
        recommendations=recommendations,
    )


def _generate_recommendations(alert: AlertEvent) -> list[str]:
    """
    Produce prioritised, actionable recommendations from the alert.

    Combines:
      1. Immediate containment actions (risk-score-gated)
      2. MITRE ATT&CK tactic-specific mitigations
      3. Graph propagation path hardening
    """
    recs: list[str] = []

    # -- Immediate containment (high / critical alerts) ----------------------
    if alert.risk_score >= 85:
        recs.append(
            f"IMMEDIATE: Isolate {alert.device_id} into a quarantine VLAN "
            "and disable all non-management network access."
        )
    elif alert.risk_score >= 65:
        recs.append(
            f"Restrict {alert.device_id} to its home subnet and block all "
            "inter-segment traffic until the root cause is confirmed."
        )
    else:
        recs.append(
            f"Flag {alert.device_id} for increased monitoring. Confirm whether "
            "the anomaly represents a genuine threat before isolating."
        )

    # -- Block outbound C2 / exfil traffic -----------------------------------
    recs.append(
        f"Block all outbound connections from {alert.device_id} to unrecognised "
        "external endpoints at the perimeter firewall."
    )

    # -- MITRE tactic-specific mitigations -----------------------------------
    tactic_mitigations = _MITRE_MITIGATIONS.get(alert.mitre.tactic, _DEFAULT_MITIGATIONS)
    recs.extend(tactic_mitigations)

    # -- Graph propagation awareness -----------------------------------------
    if alert.graph.next_targets:
        targets = ", ".join(alert.graph.next_targets)
        recs.append(
            f"Place elevated monitoring on likely next-hop targets: {targets}."
        )

    if len(alert.graph.path) > 1:
        path_str = " → ".join(alert.graph.path)
        recs.append(
            f"Run firmware integrity verification on all devices in the attack path: {path_str}."
        )

    # -- Forensics and logging -----------------------------------------------
    recs.append(
        "Preserve full packet capture and device logs before any remediation to "
        "support post-incident forensic analysis."
    )

    return recs

