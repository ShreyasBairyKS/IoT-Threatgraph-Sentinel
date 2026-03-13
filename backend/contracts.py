"""
contracts.py - Frozen Pydantic models for all inter-service contracts.

These models are the single source of truth for payload validation across
P1 → P3, P2 → P3, and P3 → P4. Do NOT modify field names without a
4-member team approval. (See docs/TEAM_EXECUTION_GUIDE.md Section 4)
"""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field
from datetime import datetime


# ---------------------------------------------------------------------------
# 4.1 Feature Window Contract (P1 → P2/P3)
# ---------------------------------------------------------------------------

class FeatureWindow(BaseModel):
    window_start: datetime
    window_end: datetime
    device_id: str
    features: dict[str, float] = Field(
        ...,
        description=(
            "Named feature values: flow_duration_mean, packet_rate, byte_volume, "
            "port_entropy, unique_dest_ips, tcp_ratio, udp_ratio, iat_mean, iat_std"
        ),
    )


# ---------------------------------------------------------------------------
# 4.2 Anomaly Result Contract (P1 → P2/P3)
# ---------------------------------------------------------------------------

class AnomalyScores(BaseModel):
    isolation_forest: float
    autoencoder: float
    final_risk: float
    confidence: Literal["low", "medium", "high"]


class AnomalyResult(BaseModel):
    timestamp: datetime
    device_id: str
    device_type: str
    scores: AnomalyScores
    reason_codes: list[str]
    explanations: list[str]


# ---------------------------------------------------------------------------
# 4.3 Graph Enrichment Contract (P2 → P3/P4)
# ---------------------------------------------------------------------------

class NextTargetPrediction(BaseModel):
    device_id: str
    score: float
    why: str


class MITRETag(BaseModel):
    tactic: str
    technique: str


class GraphEnrichment(BaseModel):
    timestamp: datetime
    source_device: str
    propagation_risk: float = Field(..., ge=0.0, le=1.0)
    neighbors: list[str]
    next_target_prediction: list[NextTargetPrediction]
    attack_paths: list[list[str]]
    mitre: MITRETag


# ---------------------------------------------------------------------------
# 4.4 Alert Event Contract (P3 → P4 over WebSocket)
# ---------------------------------------------------------------------------

class AlertGraph(BaseModel):
    path: list[str]
    next_targets: list[str]


class AlertEvent(BaseModel):
    event_type: Literal["alert.created"] = "alert.created"
    event_id: str
    timestamp: datetime
    severity: Literal["low", "medium", "high", "critical"]
    device_id: str
    device_type: str
    risk_score: float = Field(..., ge=0.0, le=100.0)
    confidence: Literal["low", "medium", "high"]
    reasons: list[str]
    mitre: MITRETag
    graph: AlertGraph


# ---------------------------------------------------------------------------
# 4.5 Incident Report Contract (P3 output)
# ---------------------------------------------------------------------------

class IncidentEvidence(BaseModel):
    risk_score: float
    explanations: list[str]
    mitre: list[MITRETag]


class IncidentReport(BaseModel):
    report_id: str
    generated_at: datetime
    incident_summary: str
    affected_devices: list[str]
    evidence: IncidentEvidence
    recommendations: list[str]


# ---------------------------------------------------------------------------
# Utility: Device summary (used by GET /devices)
# ---------------------------------------------------------------------------

class DeviceSummary(BaseModel):
    device_id: str
    device_type: str
    last_seen: datetime
    risk_score: float
    confidence: Optional[Literal["low", "medium", "high"]] = None
    status: Literal["normal", "suspicious", "critical"] = "normal"
