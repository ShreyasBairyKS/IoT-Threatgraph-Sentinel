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

_DEVICE_IMPORTANCE: dict[str, float] = {
    "router": 1.0,
    "nvr": 0.95,
    "access_controller": 0.9,
    "camera": 0.75,
    "thermostat": 0.45,
    "sensor": 0.35,
    "smart_plug": 0.3,
}


def _importance(device_type: str) -> float:
    return _DEVICE_IMPORTANCE.get(device_type, 0.5)


def _build_graph_enrichment(devices: list[tuple[str, str]], index: int) -> GraphEnrichment:
    source, source_type = devices[index % len(devices)]

    # Dynamic blast radius based on source importance and current propagation risk.
    # Low-importance devices should usually affect fewer neighbors.
    risk = round(0.25 + ((index % 8) / 10.0), 2)
    risk = min(risk, 0.95)
    importance = _importance(source_type)
    fanout = int(round(1 + importance * 3 + risk * 2))
    fanout = max(1, min(5, fanout))

    # Add a deterministic stride so same source does not always affect the exact same set.
    stride = 1 if importance >= 0.8 else 2 if importance >= 0.5 else 3
    neighbors = [
        devices[(index + offset * stride) % len(devices)][0]
        for offset in range(1, fanout + 1)
    ]

    tactic, technique = _MITRE_ROTATION[index % len(_MITRE_ROTATION)]

    next_targets = []
    for offset, neighbor in enumerate(neighbors, start=1):
        next_targets.append(
            NextTargetPrediction(
                device_id=neighbor,
                score=round(min(0.99, risk + 0.14 - (offset - 1) * 0.06), 2),
                why=_WHY_ROTATION[(index + offset) % len(_WHY_ROTATION)],
            )
        )

    attack_paths: list[list[str]] = []
    for path_index, neighbor in enumerate(neighbors):
        hop2 = devices[(index + fanout + path_index + 1) % len(devices)][0]
        if hop2 != source and hop2 != neighbor:
            attack_paths.append([source, neighbor, hop2])
        else:
            attack_paths.append([source, neighbor])

    return GraphEnrichment(
        timestamp=datetime.now(tz=timezone.utc),
        source_device=source,
        propagation_risk=risk,
        neighbors=neighbors,
        next_target_prediction=next_targets,
        attack_paths=attack_paths,
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
