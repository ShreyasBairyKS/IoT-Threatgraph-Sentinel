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

