from __future__ import annotations

import asyncio
import csv
import logging
import random
from datetime import datetime, timezone
from pathlib import Path
from collections import OrderedDict

from backend.config import settings
from backend.contracts import AnomalyResult, AnomalyScores, DeviceSummary, GraphEnrichment, MITRETag, NextTargetPrediction
from backend.store import ALERT_RISK_THRESHOLD, alert_store, build_alert_event, device_registry, graph_store, processing_stats, alert_context_store
from backend.ws.broadcaster import manager

logger = logging.getLogger(__name__)


def _risk_to_confidence(score: float) -> str:
    if score >= settings.CONFIDENCE_HIGH_THRESHOLD:
        return "high"
    if score >= settings.CONFIDENCE_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def _risk_to_status(score: float) -> str:
    if score >= settings.SEVERITY_CRITICAL_THRESHOLD:
        return "critical"
    if score >= settings.ALERT_RISK_THRESHOLD:
        return "suspicious"
    return "normal"


def _load_data() -> tuple[list[dict], OrderedDict[str, str]]:
    data_file = Path("data/sample_flows.csv")
    devices_map = OrderedDict()
    flows = []

    if data_file.exists():
        with data_file.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                device_id = (row.get("device_id") or "").strip()
                if not device_id:
                    continue
                flows.append(row)
                device_type = (row.get("device_type") or "unknown").strip() or "unknown"
                if device_id not in devices_map:
                    devices_map[device_id] = device_type
    
    if not flows:
        flows.append({"device_id": "live-cam-01", "device_type": "camera", "unique_dest_ips": "3"})
        devices_map["live-cam-01"] = "camera"

    return flows, devices_map


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


def _build_graph_enrichment(flow: dict, unique_devices: list[str], index: int) -> GraphEnrichment:
    source = flow["device_id"]
    
    # Take chunks of training data features
    dest_ips = int(float(flow.get("unique_dest_ips", 3))) if flow.get("unique_dest_ips") else 3
    num_neighbors = min(dest_ips, len(unique_devices) - 1)
    if num_neighbors < 1:
        num_neighbors = 1
    
    random.seed(index) # pseudo-random but repeatable per tick
    
    available_targets = [d for d in unique_devices if d != source]
    random.shuffle(available_targets)
    neighbors = available_targets[:num_neighbors]
    
    # Calculate propagation risk using packet_rate or byte_volume chunk data
    byte_vol = float(flow.get("byte_volume", 1000)) if flow.get("byte_volume") else 1000.0
    risk = max(0.1, min(0.95, 0.25 + (byte_vol % 70) / 100.0))
    
    tactic, technique = _MITRE_ROTATION[index % len(_MITRE_ROTATION)]

    predictions = []
    attack_paths = []
    for i, neighbor in enumerate(neighbors):
        pred_score = round(min(0.99, risk + (0.04 * i)), 2)
        predictions.append(
            NextTargetPrediction(
                device_id=neighbor,
                score=pred_score,
                why=_WHY_ROTATION[(index + i) % len(_WHY_ROTATION)],
            )
        )
        if random.random() > 0.5 and len(available_targets) > num_neighbors:
            hop = available_targets[num_neighbors]
            attack_paths.append([source, neighbor, hop])
        else:
            attack_paths.append([source, neighbor])

    # Ensure at least one attack path is generated if there are no neighbors
    if not attack_paths and neighbors:
        attack_paths.append([source, neighbors[0]])
    elif not attack_paths:
        attack_paths.append([source])

    return GraphEnrichment(
        timestamp=datetime.now(tz=timezone.utc),
        source_device=source,
        propagation_risk=round(risk, 2),
        neighbors=neighbors,
        next_target_prediction=predictions,
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


def _build_anomaly_result(flow: dict, index: int) -> AnomalyResult:
    device_id = flow["device_id"]
    device_type = flow.get("device_type", "unknown")
    
    # Calculate anomaly risk from data chunks
    packet_rate = float(flow.get("packet_rate", 50.0)) if flow.get("packet_rate") else 50.0
    risk = max(10.0, min(99.0, 20.0 + (packet_rate % 80)))
    
    confidence = _risk_to_confidence(risk)
    reasons = ["Traffic baseline shifted — monitoring in progress"]
    reason_codes = ["traffic_baseline_shift"]

    if risk >= ALERT_RISK_THRESHOLD:
        matrix_entry = _REASON_MATRIX[index % len(_REASON_MATRIX)]
        reason_codes = matrix_entry[0]
        # Format placeholders with plausible values derived from data instead of static index
        val = flow.get("byte_volume")
        factor = float(val) % 10 if val else round(2.5 + (index % 5) * 1.2, 1)
        if factor < 1.0: factor = 5.0
        reasons = [t.format(factor) for t in matrix_entry[1]]

    return AnomalyResult(
        timestamp=datetime.now(tz=timezone.utc),
        device_id=device_id,
        device_type=device_type,
        scores=AnomalyScores(
            isolation_forest=round(risk, 1),
            autoencoder=round(max(0.0, min(100.0, risk - 2.0)), 1),
            final_risk=round(risk, 1),
            confidence=confidence,
        ),
        reason_codes=reason_codes,
        explanations=reasons,
    )


async def realtime_stream_loop() -> None:
    """Continuously emits synthetic anomaly + graph updates as live events driven by training data chunks."""
    flows, devices_map = _load_data()
    unique_devices = list(devices_map.keys())
    
    logger.info("Real-time stream initialized with %d training flows across %d devices", len(flows), len(unique_devices))

    # Seed the registry so the UI always has devices that are present but not alerting yet.
    for device_id, device_type in devices_map.items():
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

        flow = flows[tick % len(flows)]
        
        graph = _build_graph_enrichment(flow, unique_devices, tick)
        anomaly = _build_anomaly_result(flow, tick)

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
            logger.info("Live stream alert emitted from training chunk: %s risk=%.1f", alert.event_id, alert.risk_score)
        else:
            await processing_stats.record(generated_alert=False)

        tick += 1

