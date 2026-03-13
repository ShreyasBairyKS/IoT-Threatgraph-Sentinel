from __future__ import annotations

import asyncio
import csv
import logging
import random
from datetime import datetime, timezone
from itertools import cycle
from pathlib import Path

from backend.config import settings
from backend.contracts import (
    AnomalyResult,
    AnomalyScores,
    DeviceSummary,
    GraphEnrichment,
    MITRETag,
    NextTargetPrediction,
)
from backend.routers.ingest import process_anomaly_result
from backend.store import device_registry, graph_store

logger = logging.getLogger(__name__)

_RISK_CYCLE = [12.0, 38.0, 57.0, 76.0, 91.0]
_TOPOLOGIES = ["fanout", "chain", "pivot", "mesh"]


def _confidence_from_risk(risk: float) -> str:
    if risk >= 80:
        return "high"
    if risk >= 50:
        return "medium"
    return "low"


def _mitre_for_risk(risk: float) -> MITRETag:
    if risk >= 85:
        return MITRETag(tactic="Exfiltration", technique="T1048")
    if risk >= 70:
        return MITRETag(tactic="Command and Control", technique="T1071")
    if risk >= 50:
        return MITRETag(tactic="Lateral Movement", technique="T1021")
    return MITRETag(tactic="Discovery", technique="T1046")


def _status_from_risk(risk: float) -> str:
    if risk >= 70:
        return "critical"
    if risk >= 50:
        return "suspicious"
    return "normal"


def _load_flow_rows() -> list[dict[str, str]]:
    root = Path(__file__).resolve().parents[2]
    candidates = [
        root / "data" / "external" / "synthetic_iot_flows_test.csv",
        root / "data" / "external" / "synthetic_iot_flows_train.csv",
    ]
    for path in candidates:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", newline="") as fp:
            rows = list(csv.DictReader(fp))
        if rows:
            logger.info("Synthetic stream using dataset: %s (%d rows)", path.name, len(rows))
            return rows
    logger.warning("Synthetic stream dataset missing. Using built-in fallback rows.")
    return [
        {
            "device_id": "cam-001", "device_type": "camera",
            "dst_device": "router-01", "phase": "normal",
            "packet_rate": "25.0", "byte_volume": "4200.0", "attack_stage": "benign",
        }
    ]


def _unique_devices(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: dict[str, dict[str, str]] = {}
    for row in rows:
        did = str(row.get("device_id") or row.get("src_device") or "")
        if did and did not in seen:
            seen[did] = row
    return list(seen.values())


def _build_topology(
    source: str,
    all_ids: list[str],
    topology: str,
    count: int,
) -> tuple[list[str], list[list[str]]]:
    """Return (neighbors, attack_paths) for a given topology pattern."""
    candidates = [d for d in all_ids if d != source]
    # Shuffle for variety every call
    random.shuffle(candidates)
    targets = candidates[:count]

    if not targets:
        return [source], [[source]]

    if topology == "chain":
        path = [source, *targets]
        return targets, [path]

    if topology == "pivot":
        pivot = targets[0]
        rest = targets[1:] if len(targets) > 1 else [targets[0]]
        paths = [[source, pivot, t] for t in rest]
        if not paths:
            paths = [[source, pivot]]
        return [pivot, *rest], paths

    if topology == "mesh":
        # Source talks to all targets; targets also talk to each other (first pairs)
        paths: list[list[str]] = [[source, t] for t in targets]
        for i in range(min(len(targets) - 1, 3)):
            paths.append([targets[i], targets[i + 1]])
        return targets, paths

    # fanout (default): source -> each target independently
    return targets, [[source, t] for t in targets]


async def pre_seed_devices() -> None:
    """Register all unique devices from the dataset immediately at startup."""
    rows = _load_flow_rows()
    device_rows = _unique_devices(rows)
    now = datetime.now(tz=timezone.utc)
    risk_rotation = cycle(_RISK_CYCLE)
    for row in device_rows:
        did = str(row.get("device_id") or row.get("src_device") or "unknown")
        dtype = str(row.get("device_type") or "unknown")
        risk = next(risk_rotation)
        device = DeviceSummary(
            device_id=did,
            device_type=dtype,
            last_seen=now,
            risk_score=round(risk, 1),
            confidence=_confidence_from_risk(risk),
            status=_status_from_risk(risk),
        )
        await device_registry.upsert(device)
    logger.info("Pre-seeded %d devices from dataset.", len(device_rows))


async def synthetic_stream_loop() -> None:
    """Emit varied-topology enrichment events for all devices every cycle.

    Each round:
    - Shuffles devices so the active source changes every tick.
    - Picks a random topology (fanout/chain/pivot/mesh) per device.
    - Picks a random neighbor count (2–8) so the graph shows different
      numbers of connections each cycle.
    - Cycles risk values across all severity bands.
    """
    rows = _load_flow_rows()
    device_rows = _unique_devices(rows)
    all_device_ids = [str(r.get("device_id") or r.get("src_device") or "") for r in device_rows]
    all_device_ids = [d for d in all_device_ids if d]

    await pre_seed_devices()

    risk_iter = cycle(_RISK_CYCLE)

    while True:
        now = datetime.now(tz=timezone.utc)

        # Shuffle device order each round so graph source changes dynamically
        round_rows = device_rows[:]
        random.shuffle(round_rows)

        # Pick one topology per round (consistent visual theme per cycle)
        round_topology = random.choice(_TOPOLOGIES)

        for row in round_rows:
            try:
                risk = next(risk_iter)
                device_id = str(row.get("device_id") or row.get("src_device") or "unknown-device")
                device_type = str(row.get("device_type") or "unknown")
                packet_rate = float(row.get("packet_rate") or 0.0)
                byte_volume = float(row.get("byte_volume") or 0.0)
                phase = str(row.get("phase") or "normal")
                attack_stage = str(row.get("attack_stage") or "benign")

                # Varied connection count: 2–8, weighted toward mid-range
                neighbor_count = random.choices(
                    [2, 3, 4, 5, 6, 7, 8],
                    weights=[10, 20, 25, 20, 12, 8, 5],
                )[0]

                neighbors, attack_paths = _build_topology(
                    source=device_id,
                    all_ids=all_device_ids,
                    topology=round_topology,
                    count=neighbor_count,
                )

                mitre = _mitre_for_risk(risk)
                enrichment = GraphEnrichment(
                    timestamp=now,
                    source_device=device_id,
                    propagation_risk=round(min(1.0, max(0.1, (risk / 100.0) * 0.9)), 3),
                    neighbors=neighbors,
                    next_target_prediction=[
                        NextTargetPrediction(
                            device_id=n,
                            score=round(min(0.99, 0.92 - idx * 0.08), 3),
                            why=f"{round_topology} link",
                        )
                        for idx, n in enumerate(neighbors[:5])
                    ],
                    attack_paths=attack_paths,
                    mitre=mitre,
                )
                await graph_store.update(enrichment)

                anomaly = AnomalyResult(
                    timestamp=now,
                    device_id=device_id,
                    device_type=device_type,
                    scores=AnomalyScores(
                        isolation_forest=round(max(0.0, risk - 3.5), 3),
                        autoencoder=round(min(100.0, risk + 2.1), 3),
                        final_risk=round(risk, 3),
                        confidence=_confidence_from_risk(risk),
                    ),
                    reason_codes=[
                        "synthetic_stream_tick",
                        f"topology_{round_topology}",
                        f"phase_{phase}",
                        f"stage_{attack_stage}",
                    ],
                    explanations=[
                        f"Synthetic {round_topology} stream: phase={phase}, stage={attack_stage}.",
                        f"packet_rate={packet_rate:.3f}, byte_volume={byte_volume:.3f}, connections={neighbor_count}.",
                    ],
                )
                await process_anomaly_result(anomaly, source="synthetic-stream")
            except Exception:
                logger.exception("Synthetic stream tick failed for device %s", row.get("device_id"))

        await asyncio.sleep(settings.SYNTHETIC_STREAM_INTERVAL_SECONDS)

