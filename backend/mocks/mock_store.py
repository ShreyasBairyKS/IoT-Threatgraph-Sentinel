"""
mock_store.py - In-memory mock data that satisfies all Day 1 contracts.

P4 can immediately consume these endpoints while P1 and P2 build
their real outputs. Each payload is contract-compliant with Section 4
of docs/TEAM_EXECUTION_GUIDE.md.
"""

from datetime import datetime, timezone
from backend.contracts import (
    AlertEvent,
    AlertGraph,
    AnomalyResult,
    AnomalyScores,
    DeviceSummary,
    GraphEnrichment,
    IncidentEvidence,
    IncidentReport,
    MITRETag,
    NextTargetPrediction,
)

_NOW = datetime(2026, 3, 13, 6, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Mock devices
# ---------------------------------------------------------------------------

MOCK_DEVICES: list[DeviceSummary] = [
    DeviceSummary(
        device_id="cam-001",
        device_type="camera",
        last_seen=_NOW,
        risk_score=87.0,
        confidence="high",
        status="critical",
    ),
    DeviceSummary(
        device_id="router-02",
        device_type="router",
        last_seen=_NOW,
        risk_score=61.0,
        confidence="medium",
        status="suspicious",
    ),
    DeviceSummary(
        device_id="nvr-01",
        device_type="nvr",
        last_seen=_NOW,
        risk_score=12.0,
        confidence="low",
        status="normal",
    ),
    DeviceSummary(
        device_id="sensor-07",
        device_type="sensor",
        last_seen=_NOW,
        risk_score=5.0,
        confidence=None,
        status="normal",
    ),
    DeviceSummary(
        device_id="access-ctrl-01",
        device_type="access_controller",
        last_seen=_NOW,
        risk_score=34.0,
        confidence="medium",
        status="suspicious",
    ),
]


# ---------------------------------------------------------------------------
# Mock alerts
# ---------------------------------------------------------------------------

_MITRE_LATERAL = MITRETag(tactic="Lateral Movement", technique="T1021")

MOCK_ALERTS: list[AlertEvent] = [
    AlertEvent(
        event_id="evt_4f20",
        timestamp=_NOW,
        severity="high",
        device_id="cam-001",
        device_type="camera",
        risk_score=87.0,
        confidence="high",
        reasons=[
            "Outbound traffic is 6.8x above rolling baseline",
            "Likely propagation path detected",
        ],
        mitre=_MITRE_LATERAL,
        graph=AlertGraph(
            path=["cam-001", "router-02", "access-ctrl-01"],
            next_targets=["router-02", "nvr-01"],
        ),
    ),
    AlertEvent(
        event_id="evt_4f21",
        timestamp=_NOW,
        severity="medium",
        device_id="router-02",
        device_type="router",
        risk_score=61.0,
        confidence="medium",
        reasons=[
            "Unusual port entropy spike detected",
            "Bidirectional flow to unknown external endpoint",
        ],
        mitre=MITRETag(tactic="Command and Control", technique="T1071"),
        graph=AlertGraph(
            path=["router-02", "access-ctrl-01"],
            next_targets=["access-ctrl-01"],
        ),
    ),
]


# ---------------------------------------------------------------------------
# Mock graph enrichment
# ---------------------------------------------------------------------------

MOCK_GRAPH: GraphEnrichment = GraphEnrichment(
    timestamp=_NOW,
    source_device="cam-001",
    propagation_risk=0.81,
    neighbors=["router-02", "nvr-01", "sensor-07"],
    next_target_prediction=[
        NextTargetPrediction(device_id="router-02", score=0.88, why="high betweenness centrality"),
        NextTargetPrediction(device_id="nvr-01", score=0.79, why="frequent bidirectional flow"),
    ],
    attack_paths=[["cam-001", "router-02", "access-ctrl-01"]],
    mitre=_MITRE_LATERAL,
)


# ---------------------------------------------------------------------------
# Mock incident report
# ---------------------------------------------------------------------------

MOCK_REPORT: IncidentReport = IncidentReport(
    report_id="rep_001",
    generated_at=_NOW,
    incident_summary="Potential lateral movement initiated from cam-001",
    affected_devices=["cam-001", "router-02", "access-ctrl-01"],
    evidence=IncidentEvidence(
        risk_score=87.0,
        explanations=[
            "Outbound traffic spike",
            "Unusual destination fan-out",
        ],
        mitre=[_MITRE_LATERAL],
    ),
    recommendations=[
        "Isolate cam-001 into quarantine VLAN",
        "Block outbound connections to unseen external endpoints",
        "Run firmware integrity check on router-02",
    ],
)
