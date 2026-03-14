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
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ml.features import FEATURE_KEYS
from ml.settings import (
    CONFIDENCE_HIGH_THRESHOLD,
    CONFIDENCE_MEDIUM_THRESHOLD,
    DEFAULT_MODEL_DIR,
    REASON_MIN_RISK,
)
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
    autoencoder: Any | None         # Optional day-3 drift detector
    autoencoder_meta: dict[str, float] | None


def load_models(model_dir: str | Path = DEFAULT_MODEL_DIR) -> ModelBundle:
    """Load all trained artifacts from *model_dir*."""
    d = Path(model_dir)
    scaler = load_artifact(d / "scaler.pkl")
    iforest = load_artifact(d / "isolation_forest.pkl")
    dt_clf = load_artifact(d / "device_classifier.pkl") if (d / "device_classifier.pkl").exists() else None
    dt_classes = load_artifact(d / "device_classes.pkl") if (d / "device_classes.pkl").exists() else []
    autoencoder = load_artifact(d / "autoencoder.pkl") if (d / "autoencoder.pkl").exists() else None
    autoencoder_meta = (
        load_artifact(d / "autoencoder_meta.pkl") if (d / "autoencoder_meta.pkl").exists() else None
    )
    return ModelBundle(
        scaler=scaler,
        isolation_forest=iforest,
        device_classifier=dt_clf,
        device_classes=list(dt_classes),
        autoencoder=autoencoder,
        autoencoder_meta=autoencoder_meta,
    )


# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

def _feature_vector(features: dict[str, float]) -> np.ndarray:
    return np.array([[float(features.get(k, 0.0)) for k in FEATURE_KEYS]], dtype=np.float64)


def _if_score(models: ModelBundle, X_scaled: np.ndarray) -> float:
    """Return Isolation Forest anomaly score in [0, 100]."""
    raw = models.isolation_forest.decision_function(X_scaled)[0]
    # decision_function > 0 is normal, < 0 is anomalous.
    # We use a robust sigmoid centred around the model's determined anomaly threshold (0.0).
    # This automatically bounds the score between 0 and 100 without hardcoded linear scales.
    score = 100.0 / (1.0 + np.exp(raw))
    return float(np.clip(score, 0.0, 100.0))



def _autoencoder_score(models: ModelBundle, X_scaled: np.ndarray) -> float | None:
    """Return optional drift score in [0, 100] from reconstruction error."""
    if models.autoencoder is None:
        return None

    recon = models.autoencoder.predict(X_scaled)
    err = float(np.mean((X_scaled - recon) ** 2))

    meta = models.autoencoder_meta or {}
    mean = float(meta.get("error_mean", 0.0))
    std = float(meta.get("error_std", 1.0)) or 1.0
    z = (err - mean) / std
    
    # Apply a logistic transform on the Z-score to naturally bound the score
    # to 0-100 without relying on hardcoded scaling variables.
    # A z-score of 0 (mean error) -> 50 score. 
    # Higher z (worse reconstruction) -> closer to 100.
    score = 100.0 / (1.0 + np.exp(-z))
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
    if risk >= CONFIDENCE_HIGH_THRESHOLD:
        return "high"
    if risk >= CONFIDENCE_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def _reason_codes_and_explanations(
    models: ModelBundle,
    x_scaled: np.ndarray,
    features: dict[str, float],
    risk: float,
) -> tuple[list[str], list[str]]:
    """Generate reason codes and SHAP-like human-readable explanation strings."""
    if risk < REASON_MIN_RISK:
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
    except Exception:
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
    ae_score = _autoencoder_score(models, X_scaled)
    predicted_type = _predict_device_type(models, X_scaled, fallback=device_type)

    if ae_score is None:
        final_risk = float(np.clip(if_score, 0.0, 100.0))
    else:
        # Instead of fixed weights, compute risk considering both using a proper formula like max or weighted average.
        # Here we just take the max score among IF and AE to reflect the highest detected risk.
        final_risk = float(np.clip(max(if_score, ae_score), 0.0, 100.0))

    conf = _confidence(final_risk)
    codes, exps = _reason_codes_and_explanations(models, X_scaled, features, final_risk)

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
    ap.add_argument("--model-dir", default=DEFAULT_MODEL_DIR)
    ap.add_argument("--api-url",   default=None, help="Backend API URL to post results (e.g. http://localhost:8000/ingest/anomaly)")
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
        payload = result.to_contract_payload()
        results.append(payload)

        # Real connection: push data to backend
        if args.api_url:
            try:
                req = urllib.request.Request(
                    args.api_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req)
            except Exception as e:
                pass

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"items": results}, indent=2), encoding="utf-8")
    print(f"Wrote {len(results)} anomaly results -> {out_path}")


if __name__ == "__main__":
    main()
