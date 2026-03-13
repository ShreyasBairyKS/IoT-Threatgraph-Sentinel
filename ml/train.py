"""
ml/train.py — Train and serialize the Isolation Forest anomaly detector
and the device type classifier.

Run:
    python -m ml.train --input data/sample_flows.csv \
                        --model-dir artifacts/models

Outputs:
    artifacts/models/isolation_forest.pkl  — trained IsolationForest
    artifacts/models/device_classifier.pkl — trained RandomForestClassifier
    artifacts/models/scaler.pkl            — fitted StandardScaler
"""
from __future__ import annotations

import argparse
import pickle
from pathlib import Path

import numpy as np

from ml.features import FEATURE_KEYS, build_windows, load_csv

# ---------------------------------------------------------------------------
# Vector helpers
# ---------------------------------------------------------------------------

def windows_to_matrix(windows: list[dict]) -> tuple[np.ndarray, list[str], list[str]]:
    """
    Convert a list of FeatureWindow dicts into a (X, device_ids, device_types) tuple.

    Returns:
        X            — float array of shape (n_windows, n_features)
        device_ids   — list of device_id strings, one per row
        device_types — list of device_type strings, one per row
                       (empty string if device_type not in record)
    """
    rows = []
    device_ids = []
    device_types = []
    for w in windows:
        feat = w.get("features", {})
        row = [float(feat.get(k, 0.0)) for k in FEATURE_KEYS]
        rows.append(row)
        device_ids.append(w.get("device_id", "unknown"))
        device_types.append(w.get("device_type", ""))
    X = np.array(rows, dtype=np.float64)
    return X, device_ids, device_types


# ---------------------------------------------------------------------------
# Isolation Forest training
# ---------------------------------------------------------------------------

def train_isolation_forest(
    X: np.ndarray,
    random_state: int = 42,
    n_estimators: int = 200,
    contamination: float = 0.15,
) -> object:
    """
    Fit an IsolationForest on feature matrix X.

    contamination=0.15 means ~15 % of training windows treated as anomalies —
    reasonable for a mixed benign/attack replay dataset.
    """
    from sklearn.ensemble import IsolationForest  # type: ignore[import]

    clf = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X)
    return clf


def build_isolation_forest_meta(clf: object, X: np.ndarray) -> dict[str, float]:
    """
    Build calibration metadata from IsolationForest decision scores.

    The model threshold is represented by ``offset_``; scores below that are
    more anomalous. Persisting these stats avoids hardcoded scaling in inference.
    """
    raw = np.asarray(clf.decision_function(X), dtype=np.float64)
    mean = float(np.mean(raw)) if len(raw) else 0.0
    std = float(np.std(raw)) if len(raw) else 1.0
    return {
        "decision_mean": mean,
        "decision_std": std if std > 1e-9 else 1.0,
        "decision_p05": float(np.percentile(raw, 5)) if len(raw) else -1.0,
        "decision_p95": float(np.percentile(raw, 95)) if len(raw) else 1.0,
        "threshold_offset": float(getattr(clf, "offset_", 0.0)),
    }


def isolation_forest_score(clf: object, X: np.ndarray) -> np.ndarray:
    """
    Return anomaly scores in [0, 100] (higher = more anomalous).

    sklearn's decision_function returns negative values for anomalies;
    we invert and normalise to 0-100.
    """
    from sklearn.ensemble import IsolationForest  # type: ignore[import]

    assert isinstance(clf, IsolationForest)
    raw = clf.decision_function(X)           # lower (more negative) = more anomalous
    # Invert: anomaly score = -raw, then min-max scale to 0-100
    inverted = -raw
    lo, hi = inverted.min(), inverted.max()
    if hi == lo:
        return np.full(len(X), 50.0)
    return ((inverted - lo) / (hi - lo) * 100).clip(0, 100)


# ---------------------------------------------------------------------------
# Device type classifier training
# ---------------------------------------------------------------------------

def train_device_classifier(
    X: np.ndarray,
    device_types: list[str],
    random_state: int = 42,
    n_estimators: int = 200,
) -> tuple[object, list[str]]:
    """
    Fit a RandomForestClassifier to predict device type labels.

    Returns (classifier, label_classes).
    Rows with empty device_type are excluded from training.
    """
    from sklearn.ensemble import RandomForestClassifier  # type: ignore[import]
    from sklearn.preprocessing import LabelEncoder  # type: ignore[import]

    # Filter rows that have a label
    labelled = [(x, t) for x, t in zip(X, device_types, strict=False) if t]
    if not labelled:
        raise ValueError("No labelled device_type rows found in training data.")

    X_lab = np.array([row for row, _ in labelled])
    y_raw = [t for _, t in labelled]

    le = LabelEncoder()
    y = le.fit_transform(y_raw)

    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X_lab, y)
    return clf, list(le.classes_)


# ---------------------------------------------------------------------------
# StandardScaler fitting
# ---------------------------------------------------------------------------

def fit_scaler(X: np.ndarray) -> object:
    from sklearn.preprocessing import StandardScaler  # type: ignore[import]

    scaler = StandardScaler()
    scaler.fit(X)
    return scaler


def train_autoencoder(X: np.ndarray, random_state: int = 42, max_iter: int = 500) -> object:
    """
    Train a lightweight MLP autoencoder surrogate (X -> X reconstruction).

    This is intentionally shallow so inference remains fast during demo replay.
    """
    from sklearn.neural_network import MLPRegressor  # type: ignore[import]

    ae = MLPRegressor(
        hidden_layer_sizes=(16, 8, 16),
        activation="relu",
        solver="adam",
        max_iter=max_iter,
        random_state=random_state,
    )
    ae.fit(X, X)
    return ae


def autoencoder_error(autoencoder: object, X: np.ndarray) -> np.ndarray:
    """Return per-sample reconstruction MSE."""
    recon = autoencoder.predict(X)
    return np.mean((X - recon) ** 2, axis=1)


def build_autoencoder_meta(errors: np.ndarray) -> dict[str, float]:
    """Calibrate reconstruction errors for runtime score normalization."""
    mean = float(np.mean(errors)) if len(errors) else 0.0
    std = float(np.std(errors)) if len(errors) else 1.0
    return {
        "error_mean": mean,
        "error_std": std if std > 1e-9 else 1.0,
        "error_p95": float(np.percentile(errors, 95)) if len(errors) else 0.0,
    }


# ---------------------------------------------------------------------------
# Persist / load
# ---------------------------------------------------------------------------

def save_artifact(obj: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        pickle.dump(obj, f)
    print(f"  Saved -> {path}")


def load_artifact(path: Path) -> object:
    with path.open("rb") as f:
        return pickle.load(f)  # noqa: S301


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Train Isolation Forest and device type classifier.")
    ap.add_argument("--input",     required=True, help="Input CSV file path.")
    ap.add_argument("--model-dir", default="artifacts/models", help="Directory to save model artifacts.")
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--iforest-contamination", type=float, default=0.15)
    ap.add_argument("--iforest-estimators", type=int, default=200)
    ap.add_argument("--classifier-estimators", type=int, default=200)
    ap.add_argument("--autoencoder-max-iter", type=int, default=500)
    ap.add_argument(
        "--disable-autoencoder",
        action="store_true",
        help="Skip optional autoencoder drift model training.",
    )
    args = ap.parse_args()

    model_dir = Path(args.model_dir)
    records = load_csv(args.input)
    windows = build_windows(records)

    print(f"Loaded {len(records)} records -> {len(windows)} feature windows.")

    # Build device_id -> device_type lookup from raw records
    device_type_map: dict[str, str] = {}
    for rec in records:
        dev_id = str(rec.get("device_id", "")).strip()
        dev_type = str(rec.get("device_type", "")).strip()
        if dev_id and dev_type:
            device_type_map[dev_id] = dev_type

    # Annotate each window with device_type before matrix conversion
    for w in windows:
        w["device_type"] = device_type_map.get(w.get("device_id", ""), "")

    X, device_ids, device_types = windows_to_matrix(windows)
    print(f"Feature matrix shape: {X.shape}")

    print("Fitting StandardScaler...")
    scaler = fit_scaler(X)
    X_scaled = scaler.transform(X)
    save_artifact(scaler, model_dir / "scaler.pkl")

    print("Training Isolation Forest...")
    if_clf = train_isolation_forest(
        X_scaled,
        random_state=args.random_state,
        n_estimators=args.iforest_estimators,
        contamination=args.iforest_contamination,
    )
    save_artifact(if_clf, model_dir / "isolation_forest.pkl")
    save_artifact(build_isolation_forest_meta(if_clf, X_scaled), model_dir / "isolation_forest_meta.pkl")

    if not args.disable_autoencoder:
        print("Training optional autoencoder drift model...")
        ae = train_autoencoder(
            X_scaled,
            random_state=args.random_state,
            max_iter=args.autoencoder_max_iter,
        )
        ae_errors = autoencoder_error(ae, X_scaled)
        ae_meta = build_autoencoder_meta(ae_errors)
        save_artifact(ae, model_dir / "autoencoder.pkl")
        save_artifact(ae_meta, model_dir / "autoencoder_meta.pkl")
        print(
            f"  Autoencoder calibration mean={ae_meta['error_mean']:.6f} std={ae_meta['error_std']:.6f}"
        )
    else:
        print("Skipping autoencoder training (--disable-autoencoder).")

    print("Training device type classifier...")
    dt_clf, classes = train_device_classifier(
        X_scaled,
        device_types,
        random_state=args.random_state,
        n_estimators=args.classifier_estimators,
    )
    save_artifact(dt_clf, model_dir / "device_classifier.pkl")
    save_artifact(classes, model_dir / "device_classes.pkl")

    print(f"\nDone. Classes learned: {classes}")

    # Quick sanity check
    scores = isolation_forest_score(if_clf, X_scaled)
    for dev_id, score in zip(device_ids, scores, strict=False):
        print(f"  {dev_id:<25}  IF score: {score:6.1f}")



if __name__ == "__main__":
    main()
