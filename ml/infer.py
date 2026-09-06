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
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ml.features import FEATURE_KEYS, feature_row
from ml.score_window import Confidence, ScoreResult, _iso_utc_now
from ml.train import load_artifact

logger = logging.getLogger(__name__)

# Set once a SHAP explanation attempt fails, so the fallback-in-use warning
# below is logged a single time per process instead of on every inference.
_shap_fallback_warned = False

# ---------------------------------------------------------------------------
# Model bundle
# ---------------------------------------------------------------------------

@dataclass
class ModelBundle:
    scaler: Any
    isolation_forest: Any
    isolation_forest_meta: dict[str, float] | None
    device_classifier: Any          # None if not available
    device_classes: list[str]       # label list matching classifier output
    autoencoder: Any | None         # Optional day-3 drift detector
    autoencoder_meta: dict[str, float] | None


@dataclass(frozen=True)
class InferenceConfig:
    confidence_medium_threshold: float = 50.0
    confidence_high_threshold: float = 80.0
    explanation_risk_threshold: float = 70.0
    iforest_sigmoid_scale: float = 1.0
    iforest_default_center: float = 0.0
    autoencoder_z_gain: float = 20.0
    fusion_iforest_weight: float = 0.7


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def load_inference_config() -> InferenceConfig:
    cfg = InferenceConfig(
        confidence_medium_threshold=_env_float("ML_CONFIDENCE_MEDIUM_THRESHOLD", 50.0),
        confidence_high_threshold=_env_float("ML_CONFIDENCE_HIGH_THRESHOLD", 80.0),
        explanation_risk_threshold=_env_float("ML_EXPLANATION_RISK_THRESHOLD", 70.0),
        iforest_sigmoid_scale=max(1e-6, _env_float("ML_IFOREST_SIGMOID_SCALE", 1.0)),
        iforest_default_center=_env_float("ML_IFOREST_DEFAULT_CENTER", 0.0),
        autoencoder_z_gain=_env_float("ML_AUTOENCODER_Z_GAIN", 20.0),
        fusion_iforest_weight=_env_float("ML_FUSION_IFOREST_WEIGHT", 0.7),
    )
    w = min(1.0, max(0.0, cfg.fusion_iforest_weight))
    return InferenceConfig(
        confidence_medium_threshold=cfg.confidence_medium_threshold,
        confidence_high_threshold=max(cfg.confidence_medium_threshold, cfg.confidence_high_threshold),
        explanation_risk_threshold=cfg.explanation_risk_threshold,
        iforest_sigmoid_scale=max(1e-6, cfg.iforest_sigmoid_scale),
        iforest_default_center=cfg.iforest_default_center,
        autoencoder_z_gain=cfg.autoencoder_z_gain,
        fusion_iforest_weight=w,
    )


def load_models(model_dir: str | Path = "artifacts/models") -> ModelBundle:
    """Load all trained artifacts from *model_dir*."""
    d = Path(model_dir)
    scaler = load_artifact(d / "scaler.pkl")
    iforest = load_artifact(d / "isolation_forest.pkl")
    iforest_meta = load_artifact(d / "isolation_forest_meta.pkl") if (d / "isolation_forest_meta.pkl").exists() else None
    dt_clf = load_artifact(d / "device_classifier.pkl") if (d / "device_classifier.pkl").exists() else None
    dt_classes = load_artifact(d / "device_classes.pkl") if (d / "device_classes.pkl").exists() else []
    autoencoder = load_artifact(d / "autoencoder.pkl") if (d / "autoencoder.pkl").exists() else None
    autoencoder_meta = (
        load_artifact(d / "autoencoder_meta.pkl") if (d / "autoencoder_meta.pkl").exists() else None
    )
    return ModelBundle(
        scaler=scaler,
        isolation_forest=iforest,
        isolation_forest_meta=iforest_meta,
        device_classifier=dt_clf,
        device_classes=list(dt_classes),
        autoencoder=autoencoder,
        autoencoder_meta=autoencoder_meta,
    )


# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

def _feature_vector(features: dict[str, float]) -> np.ndarray:
    return np.array([feature_row(features, FEATURE_KEYS)], dtype=np.float64)


def _if_score(models: ModelBundle, X_scaled: np.ndarray, cfg: InferenceConfig) -> float:
    """Return Isolation Forest anomaly score in [0, 100]."""
    raw = models.isolation_forest.decision_function(X_scaled)[0]
    raw_f = float(raw)
    meta = models.isolation_forest_meta or {}
    threshold_center = float(meta.get("threshold_offset", cfg.iforest_default_center))
    std = float(meta.get("decision_std", 1.0))
    scale = max(1e-6, std * cfg.iforest_sigmoid_scale)
    anomaly_delta = (threshold_center - raw_f) / scale
    score = 100.0 / (1.0 + np.exp(-anomaly_delta))
    return float(np.clip(score, 0.0, 100.0))


def _autoencoder_score(models: ModelBundle, X_scaled: np.ndarray, cfg: InferenceConfig) -> float | None:
    """Return optional drift score in [0, 100] from reconstruction error."""
    if models.autoencoder is None:
        return None

    recon = models.autoencoder.predict(X_scaled)
    err = float(np.mean((X_scaled - recon) ** 2))

    meta = models.autoencoder_meta or {}
    mean = float(meta.get("error_mean", 0.0))
    std = float(meta.get("error_std", 1.0)) or 1.0
    z = (err - mean) / std
    score = 50.0 + z * cfg.autoencoder_z_gain
    return float(np.clip(score, 0.0, 100.0))


def _predict_device_type(models: ModelBundle, X_scaled: np.ndarray, fallback: str) -> str:
    if models.device_classifier is None or not models.device_classes:
        return fallback
    idx = int(models.device_classifier.predict(X_scaled)[0])
    classes = models.device_classes
    if 0 <= idx < len(classes):
        return classes[idx]
    return fallback


def _confidence(risk: float, cfg: InferenceConfig | None = None) -> Confidence:
    c = cfg or load_inference_config()
    if risk >= c.confidence_high_threshold:
        return "high"
    if risk >= c.confidence_medium_threshold:
        return "medium"
    return "low"


def _reason_codes_and_explanations(
    models: ModelBundle,
    x_scaled: np.ndarray,
    features: dict[str, float],
    risk: float,
    cfg: InferenceConfig | None = None,
) -> tuple[list[str], list[str]]:
    """Generate reason codes and SHAP-like human-readable explanation strings."""
    c = cfg or load_inference_config()
    if risk < c.explanation_risk_threshold:
        return [], []

    codes: list[str] = []
    exps: list[str] = []

    # Preferred path: use SHAP if available to rank feature influence.
    try:
        import shap  # type: ignore[import-not-found]

        explainer = shap.TreeExplainer(models.isolation_forest)
        values = explainer.shap_values(x_scaled)
        if isinstance(values, list):
            vals = np.asarray(values[0]).reshape(-1)
        else:
            vals = np.asarray(values).reshape(-1)

        ranked_idx = np.argsort(np.abs(vals))[::-1][:3]
        for idx in ranked_idx:
            feat = FEATURE_KEYS[int(idx)]
            contrib = float(vals[int(idx)])
            direction = "increased" if contrib >= 0 else "reduced"
            codes.append(f"shap_{feat}")
            exps.append(
                f"SHAP indicates {feat} {direction} anomaly likelihood (contribution {contrib:+.3f})."
            )
    except Exception as exc:
        global _shap_fallback_warned
        if not _shap_fallback_warned:
            logger.warning(
                "SHAP explanation unavailable (%s: %s); falling back to z-score deviation "
                "ranking for all subsequent inferences in this process.",
                type(exc).__name__, exc,
            )
            _shap_fallback_warned = True
        # Fallback path: rank features by normalized deviation from the scaler baseline.
        means = np.asarray(getattr(models.scaler, "mean_", np.zeros(len(FEATURE_KEYS)))).reshape(-1)
        scales = np.asarray(getattr(models.scaler, "scale_", np.ones(len(FEATURE_KEYS)))).reshape(-1)
        raw = np.asarray([float(features.get(k, 0.0)) for k in FEATURE_KEYS], dtype=np.float64)
        z = np.abs((raw - means) / np.where(scales == 0, 1.0, scales))
        ranked_idx = np.argsort(z)[::-1][:3]
        for idx in ranked_idx:
            feat = FEATURE_KEYS[int(idx)]
            codes.append(f"feature_deviation_{feat}")
            exps.append(
                f"{feat} deviates from baseline by z-score {float(z[int(idx)]):.2f}, raising anomaly risk."
            )

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

    # Ensure at least 2 explanations for alerted devices
    if risk >= 60 and len(exps) < 2:
        codes.append("anomaly_model_flag")
        exps.append("Isolation Forest model flagged this device window as a statistical anomaly")
    if risk >= 80 and len(exps) < 3:
        codes.append("critical_risk_threshold")
        exps.append("Risk score exceeds critical threshold — immediate containment recommended")

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
    cfg = load_inference_config()
    X_raw = _feature_vector(features)
    X_scaled = models.scaler.transform(X_raw)

    if_score = _if_score(models, X_scaled, cfg)
    ae_score = _autoencoder_score(models, X_scaled, cfg)
    predicted_type = _predict_device_type(models, X_scaled, fallback=device_type)

    if ae_score is None:
        final_risk = float(np.clip(if_score, 0.0, 100.0))
    else:
        ae_weight = 1.0 - cfg.fusion_iforest_weight
        final_risk = float(np.clip(cfg.fusion_iforest_weight * if_score + ae_weight * ae_score, 0.0, 100.0))

    conf = _confidence(final_risk, cfg)
    codes, exps = _reason_codes_and_explanations(models, X_scaled, features, final_risk, cfg)

    return ScoreResult(
        timestamp=ts,
        device_id=device_id,
        device_type=predicted_type or device_type,
        isolation_forest=if_score,
        autoencoder=ae_score,
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
