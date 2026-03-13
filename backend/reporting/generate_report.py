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


# Playbooks keyed by MITRE tactic
_TACTIC_PLAYBOOKS: dict[str, list[str]] = {
    "Lateral Movement": [
        "Apply micro-segmentation rules to block east-west traffic between IoT zones.",
        "Rotate SSH/API credentials on all devices in the attack path.",
        "Review and tighten firewall ACLs for lateral inter-device communication.",
    ],
    "Exfiltration": [
        "Enable DPI on egress interface to detect tunnelled data exfiltration.",
        "Apply egress bandwidth caps and alert on sustained high-volume outbound flows.",
        "Verify and revoke any unauthorised API keys or outbound OAuth tokens.",
    ],
    "Impact": [
        "Take a forensic snapshot of the device state before performing remediation.",
        "Restore device configuration from a known-good backup immediately.",
        "Audit all actuator commands issued in the last 24 hours for tampering.",
    ],
    "Discovery": [
        "Enable network scanning detection and rate-limit ARP/ICMP on the segment.",
        "Disable SNMP public community strings across the IoT subnet.",
        "Review mDNS and UPnP exposure on the affected network segment.",
    ],
    "Command and Control": [
        "Block all outbound connections from the device to non-allowlisted IPs.",
        "Deploy DNS sinkholing for C2 domains identified in threat intelligence feeds.",
        "Analyse process memory on the device for injected shellcode or beacons.",
    ],
}

_DEVICE_TYPE_RECS: dict[str, str] = {
    "camera": "Disable RTSP public streaming and rotate camera authentication credentials.",
    "router": "Re-flash router firmware and audit port-forwarding / NAT rules immediately.",
    "sensor": "Verify sensor calibration data integrity — spoofed readings may mask the breach.",
    "nvr": "Preserve all NVR recordings as forensic evidence before any remediation step.",
    "access_control": "Revoke all issued access tokens and trigger a full badge-audit for the affected zone.",
    "thermostat": "Reset HVAC controller to manual mode and inspect last 48 h of setpoint commands.",
}

_REASON_RECS: dict[str, str] = {
    "outbound_volume_spike": "Throttle outbound bandwidth and set an alert threshold at 2× 7-day baseline.",
    "dest_ip_diversity_jump": "Block all newly seen destination IPs and submit them to your threat intel platform.",
    "traffic_baseline_shift": "Capture a new 24 h baseline only after the incident is fully contained.",
    "port_entropy_high": "Inspect for port-scanning activity and apply protocol whitelisting on the device.",
    "iat_anomaly": "Co-relate inter-arrival time spikes with scheduled tasks or cron jobs on the device.",
}


def _generate_recommendations(alert: AlertEvent) -> list[str]:
    """
    Context-sensitive, per-alert recommendations.
    Varies by severity, MITRE tactic, device type, and surfaced reason codes.
    """
    recs: list[str] = []

    # 1. Severity-gated immediate action
    if alert.risk_score >= 85:
        recs.append(
            f"CRITICAL: Immediately isolate {alert.device_id} into a quarantine VLAN "
            f"and page the on-call security engineer."
        )
    elif alert.risk_score >= 70:
        recs.append(
            f"HIGH: Move {alert.device_id} to a restricted network segment within 15 minutes "
            f"and begin incident triage."
        )
    else:
        recs.append(
            f"Block outbound connections from {alert.device_id} to unknown external endpoints "
            f"pending investigation."
        )

    # 2. MITRE-tactic playbook (3 entries, pick first 2 to keep report concise)
    tactic_key = alert.mitre.tactic
    for tactic_rec in _TACTIC_PLAYBOOKS.get(tactic_key, [
        "Review device logs and correlate with SIEM for additional indicators.",
        "Update threat intelligence feeds and re-scan the affected subnet.",
    ])[:2]:
        recs.append(tactic_rec)

    # 3. Device-type specific recommendation
    dtype_rec = _DEVICE_TYPE_RECS.get(alert.device_type)
    if dtype_rec:
        recs.append(dtype_rec)

    # 4. Reason-code driven recommendations (up to 2)
    for code in alert.reasons[:2]:
        # match on any known code key substring
        for key, rec in _REASON_RECS.items():
            if key in code.lower().replace(" ", "_") and rec not in recs:
                recs.append(rec)
                break

    # 5. Propagation path hardening
    if len(alert.graph.path) > 1:
        recs.append(
            f"Harden the attack path {' → '.join(alert.graph.path)}: "
            f"apply inter-zone firewall rules between each hop."
        )

    # 6. Next-target monitoring
    if alert.graph.next_targets:
        targets = ", ".join(alert.graph.next_targets)
        recs.append(
            f"Place {targets} under enhanced monitoring — ML model predicts them as "
            f"next propagation targets (technique {alert.mitre.technique})."
        )

    return recs
