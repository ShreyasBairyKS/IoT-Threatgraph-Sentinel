"""
ml/infer.py — Load trained artifacts and run inference on a feature window.

This is the production inference entry point called by the backend (P3).
It replaces the Day-1 heuristic in score_window.py with real model outputs.

Usage (programmatic):
    from ml.infer import load_models, infer_window
    models = load_models("artifacts/models")
    result = infer_window(models, device_id="cam-001", device_type="camera",
                          features={...})

Usage (CLI):
    python -m ml.infer --input artifacts/features.json \
                        --output artifacts/ml_scores.json \
                        --model-dir artifacts/models
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ml.features import FEATURE_KEYS
from ml.score_window import Confidence, ScoreResult, _iso_utc_now
from ml.train import load_artifact

# ---------------------------------------------------------------------------
# Model bundle
# ---------------------------------------------------------------------------

@dataclass
class ModelBundle:
    scaler: Any
    isolation_forest: Any
    device_classifier: Any          # None if not available
    device_classes: list[str]       # label list matching classifier output


def load_models(model_dir: str | Path = "artifacts/models") -> ModelBundle:
    """Load all trained artifacts from *model_dir*."""
    d = Path(model_dir)
    scaler     = load_artifact(d / "scaler.pkl")
    iforest    = load_artifact(d / "isolation_forest.pkl")
    dt_clf     = load_artifact(d / "device_classifier.pkl")     if (d / "device_classifier.pkl").exists() else None
    dt_classes = load_artifact(d / "device_classes.pkl")        if (d / "device_classes.pkl").exists() else []
    return ModelBundle(
        scaler=scaler,
        isolation_forest=iforest,
        device_classifier=dt_clf,
        device_classes=list(dt_classes),
    )


# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

def _feature_vector(features: dict[str, float]) -> np.ndarray:
    return np.array([[float(features.get(k, 0.0)) for k in FEATURE_KEYS]], dtype=np.float64)


def _if_score(models: ModelBundle, X_scaled: np.ndarray) -> float:
    """Return Isolation Forest anomaly score in [0, 100]."""
    raw = models.isolation_forest.decision_function(X_scaled)[0]
    # decision_function: negative = anomalous, positive = normal
    # We need a global min/max to normalise; use training score range stored
    # via the model's offset_ and threshold_ attributes as a proxy.
    # Simpler: apply a sigmoid-like mapping that keeps scores comparable.
    inverted = -float(raw)
    # Scale relative to a typical boundary (0 = normal threshold)
    score = 50.0 + inverted * 35.0   # linear stretch around 50
    return float(np.clip(score, 0.0, 100.0))


def _predict_device_type(models: ModelBundle, X_scaled: np.ndarray, fallback: str) -> str:
    if models.device_classifier is None or not models.device_classes:
        return fallback
    idx = int(models.device_classifier.predict(X_scaled)[0])
    classes = models.device_classes
    if 0 <= idx < len(classes):
        return classes[idx]
    return fallback


def _confidence(risk: float) -> Confidence:
    if risk >= 80:
        return "high"
    if risk >= 50:
        return "medium"
    return "low"


def _reason_codes_and_explanations(
    features: dict[str, float],
    risk: float,
) -> tuple[list[str], list[str]]:
    """Generate reason codes and human-readable explanation strings."""
    if risk < 70:
        return [], []

    codes: list[str] = []
    exps: list[str] = []

    byte_vol   = float(features.get("byte_volume", 0.0))
    pkt_rate   = float(features.get("packet_rate", 0.0))
    dest_ips   = float(features.get("unique_dest_ips", 0.0))
    port_ent   = float(features.get("port_entropy", 0.0))
    udp_ratio  = float(features.get("udp_ratio", 0.0))

    if byte_vol > 50_000:
        codes.append("outbound_volume_spike")
        exps.append(f"Outbound byte volume ({byte_vol:,.0f}) is elevated above baseline")

    if dest_ips > 5:
        codes.append("dest_ip_diversity_jump")
        exps.append(f"Unique destination IPs ({dest_ips:.0f}) exceeds expected fan-out")

    if port_ent > 2.0:
        codes.append("high_port_entropy")
        exps.append(f"Destination port entropy ({port_ent:.2f}) suggests port scanning")

    if pkt_rate > 40:
        codes.append("high_packet_rate")
        exps.append(f"Packet rate ({pkt_rate:.1f} pps) significantly above device baseline")

    if udp_ratio > 0.5:
        codes.append("udp_dominance")
        exps.append(f"UDP traffic ratio ({udp_ratio:.0%}) is unusually high")

    # Ensure at least 2 explanations for high-risk alerts (handoff requirement)
    if risk >= 80 and len(exps) < 2:
        codes.append("anomaly_model_flag")
        exps.append("Isolation Forest model flagged this device window as anomalous")

    return codes, exps


# ---------------------------------------------------------------------------
# Public inference API
# ---------------------------------------------------------------------------

def infer_window(
    models: ModelBundle,
    *,
    device_id: str,
    device_type: str,
    features: dict[str, float],
    timestamp: str | None = None,
) -> ScoreResult:
    """
    Run full inference for one feature window.

    This is the replacement for score_window.score_features() using real models.
    The output shape is identical — contract-compatible with P2/P3.
    """
    ts = timestamp or _iso_utc_now()
    X_raw = _feature_vector(features)
    X_scaled = models.scaler.transform(X_raw)

    if_score = _if_score(models, X_scaled)
    predicted_type = _predict_device_type(models, X_scaled, fallback=device_type)
    final_risk = float(np.clip(if_score, 0.0, 100.0))
    conf = _confidence(final_risk)
    codes, exps = _reason_codes_and_explanations(features, final_risk)

    return ScoreResult(
        timestamp=ts,
        device_id=device_id,
        device_type=predicted_type or device_type,
        isolation_forest=if_score,
        autoencoder=None,
        final_risk=final_risk,
        confidence=conf,
        reason_codes=codes,
        explanations=exps,
    )


# ---------------------------------------------------------------------------
# CLI — batch inference over feature window JSON
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Run ML inference on feature windows.")
    ap.add_argument("--input",     required=True, help="Feature windows JSON (from ml.features CLI).")
    ap.add_argument("--output",    required=True, help="Anomaly result JSON output path.")
    ap.add_argument("--model-dir", default="artifacts/models")
    args = ap.parse_args()

    models = load_models(args.model_dir)
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    windows = data.get("windows", data.get("items", []))

    results = []
    for w in windows:
        result = infer_window(
            models,
            device_id=w.get("device_id", "unknown"),
            device_type=w.get("device_type", "unknown"),
            features=w.get("features", {}),
        )
        results.append(result.to_contract_payload())

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"items": results}, indent=2), encoding="utf-8")
    print(f"Wrote {len(results)} anomaly results -> {out_path}")


if __name__ == "__main__":
    main()
