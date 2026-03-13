from __future__ import annotations

import asyncio
import csv
import logging
from datetime import datetime, timezone
from pathlib import Path

from backend.config import settings
from backend.contracts import AnomalyResult, AnomalyScores, DeviceSummary, GraphEnrichment, MITRETag, NextTargetPrediction
from backend.store import ALERT_RISK_THRESHOLD, alert_store, build_alert_event, device_registry, graph_store, processing_stats, alert_context_store
from backend.ws.broadcaster import manager

logger = logging.getLogger(__name__)


def _risk_to_confidence(score: float) -> str:
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def _risk_to_status(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "suspicious"
    return "normal"


def _load_devices() -> list[tuple[str, str]]:
    data_file = Path("data/sample_flows.csv")
    if not data_file.exists():
        return [
            ("live-cam-01", "camera"),
            ("live-router-01", "router"),
            ("live-sensor-01", "sensor"),
        ]

    devices: dict[str, str] = {}
    with data_file.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            device_id = (row.get("device_id") or "").strip()
            if not device_id:
                continue
            device_type = (row.get("device_type") or "unknown").strip() or "unknown"
            devices[device_id] = device_type

    return list(devices.items()) or [("live-device-01", "unknown")]


_MITRE_ROTATION: list[tuple[str, str]] = [
    ("Lateral Movement", "T1021"),
    ("Exfiltration", "T1048"),
    ("Command and Control", "T1071"),
    ("Discovery", "T1046"),
    ("Impact", "T1489"),
    ("Lateral Movement", "T1210"),
    ("Exfiltration", "T1041"),
    ("Discovery", "T1083"),
]

_WHY_ROTATION: list[str] = [
    "high betweenness centrality",
    "frequent bidirectional flow",
    "open management port exposed",
    "shared subnet with source device",
    "historical lateral movement observed",
    "high eigenvector centrality in IoT graph",
]


def _build_graph_enrichment(devices: list[tuple[str, str]], index: int) -> GraphEnrichment:
    source = devices[index % len(devices)][0]
    n1 = devices[(index + 1) % len(devices)][0]
    n2 = devices[(index + 2) % len(devices)][0]
    risk = round(0.25 + ((index % 8) / 10.0), 2)
    risk = min(risk, 0.95)
    tactic, technique = _MITRE_ROTATION[index % len(_MITRE_ROTATION)]

    return GraphEnrichment(
        timestamp=datetime.now(tz=timezone.utc),
        source_device=source,
        propagation_risk=risk,
        neighbors=[n1, n2],
        next_target_prediction=[
            NextTargetPrediction(
                device_id=n1,
                score=round(min(0.99, risk + 0.12), 2),
                why=_WHY_ROTATION[index % len(_WHY_ROTATION)],
            ),
            NextTargetPrediction(
                device_id=n2,
                score=round(min(0.99, risk + 0.04), 2),
                why=_WHY_ROTATION[(index + 3) % len(_WHY_ROTATION)],
            ),
        ],
        attack_paths=[[source, n1], [source, n2]],
        mitre=MITRETag(tactic=tactic, technique=technique),
    )


_REASON_MATRIX: list[tuple[list[str], list[str]]] = [
    (["outbound_volume_spike", "dest_ip_diversity_jump"],
     ["Outbound traffic is {:.0f}× above 7-day rolling baseline", "Unique destination IP count surged from 2 to 11"]),
    (["port_entropy_high", "outbound_volume_spike"],
     ["Port entropy score is critically elevated at {:.2f} bits", "High-rate scanning pattern detected on outbound interface"]),
    (["iat_anomaly", "dest_ip_diversity_jump"],
     ["Inter-arrival time variance is {:.1f}× higher than baseline", "Connections spreading to new geographic IP blocks"]),
    (["outbound_volume_spike", "port_entropy_high"],
     ["Byte volume spike: {:.0f} MB/s vs 0.4 MB/s baseline", "Uncommon protocol distribution detected in outbound flows"]),
]


def _build_anomaly_result(device_id: str, device_type: str, index: int) -> AnomalyResult:
    risk_pattern = [28.0, 41.0, 55.0, 68.0, 79.0, 91.0, 62.0, 84.0]
    risk = risk_pattern[index % len(risk_pattern)]
    confidence = _risk_to_confidence(risk)
    reasons = ["Traffic baseline shifted — monitoring in progress"]
    reason_codes = ["traffic_baseline_shift"]

    if risk >= ALERT_RISK_THRESHOLD:
        matrix_entry = _REASON_MATRIX[index % len(_REASON_MATRIX)]
        reason_codes = matrix_entry[0]
        # Format placeholders with plausible values derived from index
        factor = round(2.5 + (index % 5) * 1.2, 1)
        reasons = [t.format(factor) for t in matrix_entry[1]]

    return AnomalyResult(
        timestamp=datetime.now(tz=timezone.utc),
        device_id=device_id,
        device_type=device_type,
        scores=AnomalyScores(
            isolation_forest=risk,
            autoencoder=max(0.0, min(100.0, risk - 2.0)),
            final_risk=risk,
            confidence=confidence,
        ),
        reason_codes=reason_codes,
        explanations=reasons,
    )


async def realtime_stream_loop() -> None:
    """Continuously emits synthetic anomaly + graph updates as live events."""
    devices = _load_devices()
    logger.info("Real-time stream initialized with %d devices", len(devices))

    # Seed the registry so the UI always has devices that are present but not alerting yet.
    for device_id, device_type in devices:
        await device_registry.upsert(
            DeviceSummary(
                device_id=device_id,
                device_type=device_type,
                last_seen=datetime.now(tz=timezone.utc),
                risk_score=12.0,
                confidence="low",
                status="normal",
            )
        )

    tick = 0
    while True:
        await asyncio.sleep(settings.REALTIME_STREAM_INTERVAL_SECONDS)

        device_id, device_type = devices[tick % len(devices)]
        graph = _build_graph_enrichment(devices, tick)
        anomaly = _build_anomaly_result(device_id, device_type, tick)

        await graph_store.update(graph)

        device = DeviceSummary(
            device_id=anomaly.device_id,
            device_type=anomaly.device_type,
            last_seen=datetime.now(tz=timezone.utc),
            risk_score=anomaly.scores.final_risk,
            confidence=anomaly.scores.confidence,
            status=_risk_to_status(anomaly.scores.final_risk),
        )
        await device_registry.upsert(device)

        if anomaly.scores.final_risk >= ALERT_RISK_THRESHOLD:
            alert = build_alert_event(anomaly, graph)
            await alert_store.add(alert)
            await processing_stats.record(generated_alert=True)
            devices_snapshot = await device_registry.get_all()
            await alert_context_store.save(alert.event_id, devices_snapshot, graph)
            await manager.broadcast(alert.model_dump(mode="json"))
            logger.info("Live stream alert emitted: %s risk=%.1f", alert.event_id, alert.risk_score)
        else:
            await processing_stats.record(generated_alert=False)

        tick += 1
