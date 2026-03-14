from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from ml.settings import (
    CONFIDENCE_HIGH_THRESHOLD,
    CONFIDENCE_MEDIUM_THRESHOLD,
    HEURISTIC_BYTE_LOG_WEIGHT,
    HEURISTIC_PACKET_RATE_WEIGHT,
    HEURISTIC_PORT_ENTROPY_WEIGHT,
    HEURISTIC_UNIQUE_DEST_WEIGHT,
    REASON_MIN_RISK,
)

Confidence = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class ScoreResult:
    timestamp: str
    device_id: str
    device_type: str
    isolation_forest: float
    autoencoder: float | None
    final_risk: float
    confidence: Confidence
    reason_codes: list[str]
    explanations: list[str]

    def to_contract_payload(self) -> dict[str, Any]:
        scores: dict[str, Any] = {
            "isolation_forest": float(self.isolation_forest),
            "final_risk": float(self.final_risk),
            "confidence": self.confidence,
            "autoencoder": float(self.autoencoder) if self.autoencoder is not None else 0.0,
        }

        return {
            "timestamp": self.timestamp,
            "device_id": self.device_id,
            "device_type": self.device_type,
            "scores": scores,
            "reason_codes": list(self.reason_codes),
            "explanations": list(self.explanations),
        }


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def score_features(
    *,
    device_id: str,
    device_type: str,
    features: dict[str, float],
    timestamp: str | None = None,
) -> ScoreResult:
    """
    Day-1 placeholder scoring that produces contract-valid output.

    Replace internals with a real trained Isolation Forest model in `ml/train.py`
    and load it here (artifact path defined by docs).
    """

    ts = timestamp or _iso_utc_now()
    # Heuristic Day-1 scoring that stays within 0..100 and produces varied output
    # even when raw feature magnitudes differ (e.g., byte_volume vs ratios).
    byte_volume = float(features.get("byte_volume", 0.0) or 0.0)
    packet_rate = float(features.get("packet_rate", 0.0) or 0.0)
    unique_dest_ips = float(features.get("unique_dest_ips", 0.0) or 0.0)
    port_entropy = float(features.get("port_entropy", 0.0) or 0.0)

    # log1p squashes large values, making the heuristic safer for unknown dataset magnitudes.
    # weights are tuned for demo realism, not accuracy.
    base = (
        math.log1p(max(0.0, byte_volume)) * HEURISTIC_BYTE_LOG_WEIGHT
        + math.log1p(max(0.0, packet_rate)) * HEURISTIC_PACKET_RATE_WEIGHT
        + math.log1p(max(0.0, unique_dest_ips)) * HEURISTIC_UNIQUE_DEST_WEIGHT
        + max(0.0, port_entropy) * HEURISTIC_PORT_ENTROPY_WEIGHT
    )
    if base != base:  # NaN check
        base = 0.0
    base = max(0.0, min(100.0, base))

    isolation_forest = base
    final_risk = max(0.0, min(100.0, float(isolation_forest)))

    if final_risk >= CONFIDENCE_HIGH_THRESHOLD:
        confidence: Confidence = "high"
    elif final_risk >= CONFIDENCE_MEDIUM_THRESHOLD:
        confidence = "medium"
    else:
        confidence = "low"

    reason_codes: list[str] = []
    explanations: list[str] = []
    if final_risk >= REASON_MIN_RISK:
        reason_codes = ["outbound_volume_spike", "dest_ip_diversity_jump"]
        explanations = [
            "Outbound traffic is above rolling baseline",
            "Unique destination IP count increased versus baseline",
        ]

    return ScoreResult(
        timestamp=ts,
        device_id=device_id,
        device_type=device_type,
        isolation_forest=isolation_forest,
        autoencoder=None,
        final_risk=final_risk,
        confidence=confidence,
        reason_codes=reason_codes,
        explanations=explanations,
    )

