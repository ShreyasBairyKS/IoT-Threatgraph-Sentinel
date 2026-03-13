from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import Random
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph.build_graph import build_graph_from_flows, save_graph
from graph.propagation import process_anomalies
from ml.features import FEATURE_KEYS, load_csv
from ml.infer import infer_window, load_models
from ml.train import (
    build_autoencoder_meta,
    build_isolation_forest_meta,
    fit_scaler,
    save_artifact,
    train_autoencoder,
    train_device_classifier,
    train_isolation_forest,
    windows_to_matrix,
)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _jitter_feature_value(key: str, value: float, rng: Random) -> float:
    if key in {"tcp_ratio", "udp_ratio"}:
        delta = rng.uniform(-0.03, 0.03)
        return max(0.0, min(1.0, value + delta))
    if key == "unique_dest_ips":
        delta = rng.uniform(-1.5, 1.5)
        return max(0.0, round(value + delta, 2))
    noise_scale = max(abs(value) * 0.03, 1e-3)
    return max(0.0, value + rng.uniform(-noise_scale, noise_scale))


def generate_dataset_and_windows(
    input_csv: Path,
    target_points: int,
    output_csv: Path,
    output_windows: Path,
    *,
    seed: int,
) -> list[dict[str, Any]]:
    base_rows = load_csv(input_csv)
    if not base_rows:
        raise ValueError(f"No input rows found in {input_csv}")

    rng = Random(seed)
    fieldnames = list(base_rows[0].keys())
    for required in ("device_id", "device_type", *FEATURE_KEYS):
        if required not in fieldnames:
            raise ValueError(f"Input CSV missing required column: {required}")

    rows_out: list[dict[str, str]] = []
    windows_out: list[dict[str, Any]] = []
    base_ts = datetime(2026, 3, 13, 0, 0, 0, tzinfo=timezone.utc)

    for idx in range(target_points):
        source = base_rows[idx % len(base_rows)]
        row = dict(source)

        features: dict[str, float] = {}
        for key in FEATURE_KEYS:
            original = _safe_float(source.get(key), 0.0)
            features[key] = round(_jitter_feature_value(key, original, rng), 6)
            row[key] = str(features[key])

        rows_out.append(row)

        start = base_ts + timedelta(seconds=idx)
        end = start + timedelta(seconds=60)
        windows_out.append(
            {
                "window_start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "window_end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "device_id": str(source.get("device_id", "unknown")),
                "device_type": str(source.get("device_type", "unknown")),
                "features": features,
            }
        )

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_out)

    output_windows.parent.mkdir(parents=True, exist_ok=True)
    output_windows.write_text(json.dumps({"windows": windows_out}, indent=2), encoding="utf-8")
    return windows_out


def train_models(windows: list[dict[str, Any]], model_dir: Path, random_state: int) -> None:
    X, _, device_types = windows_to_matrix(windows)
    scaler = fit_scaler(X)
    X_scaled = scaler.transform(X)

    iforest = train_isolation_forest(
        X_scaled,
        random_state=random_state,
        n_estimators=200,
        contamination=0.15,
    )

    autoencoder = train_autoencoder(
        X_scaled,
        random_state=random_state,
        max_iter=500,
    )
    ae_errors = ((X_scaled - autoencoder.predict(X_scaled)) ** 2).mean(axis=1)

    classifier, classes = train_device_classifier(
        X_scaled,
        device_types,
        random_state=random_state,
        n_estimators=200,
    )

    save_artifact(scaler, model_dir / "scaler.pkl")
    save_artifact(iforest, model_dir / "isolation_forest.pkl")
    save_artifact(build_isolation_forest_meta(iforest, X_scaled), model_dir / "isolation_forest_meta.pkl")
    save_artifact(autoencoder, model_dir / "autoencoder.pkl")
    save_artifact(build_autoencoder_meta(ae_errors), model_dir / "autoencoder_meta.pkl")
    save_artifact(classifier, model_dir / "device_classifier.pkl")
    save_artifact(classes, model_dir / "device_classes.pkl")


def run_inference(
    windows: list[dict[str, Any]],
    model_dir: Path,
    output_scores: Path,
) -> list[dict[str, Any]]:
    bundle = load_models(model_dir)
    items: list[dict[str, Any]] = []

    for window in windows:
        result = infer_window(
            bundle,
            device_id=str(window.get("device_id", "unknown")),
            device_type=str(window.get("device_type", "unknown")),
            features=dict(window.get("features", {})),
            timestamp=str(window.get("window_end")),
        )
        items.append(result.to_contract_payload())

    output_scores.parent.mkdir(parents=True, exist_ok=True)
    output_scores.write_text(json.dumps({"items": items}, indent=2), encoding="utf-8")
    return items


def run_graph_phase(input_csv: Path, scores_path: Path, graph_path: Path, enrichment_path: Path) -> int:
    graph = build_graph_from_flows(str(input_csv))
    save_graph(graph, str(graph_path))

    process_anomalies(
        graph_path=str(graph_path),
        scores_path=str(scores_path),
        output_path=str(enrichment_path),
    )

    payload = json.loads(enrichment_path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return len(payload)
    return 1


def _cli() -> None:
    ap = argparse.ArgumentParser(
        description="Run integrated P1->P2 pipeline with the new ML model on N datapoints."
    )
    ap.add_argument("--input", default="data/sample_flows.csv", help="Base CSV input")
    ap.add_argument("--datapoints", type=int, default=5000, help="Target datapoints to generate")
    ap.add_argument("--artifacts-dir", default="artifacts", help="Artifact output directory")
    ap.add_argument("--seed", type=int, default=42, help="Random seed")
    args = ap.parse_args()

    if args.datapoints <= 0:
        raise ValueError("--datapoints must be > 0")

    artifacts_dir = Path(args.artifacts_dir)
    model_dir = artifacts_dir / "models"

    input_csv = Path(args.input)
    csv_5000 = artifacts_dir / f"sample_flows_{args.datapoints}.csv"
    windows_path = artifacts_dir / f"features_{args.datapoints}.json"
    scores_path = artifacts_dir / f"ml_scores_{args.datapoints}.json"
    graph_path = artifacts_dir / f"graph_{args.datapoints}.json"
    enrichment_path = artifacts_dir / f"graph_enrichment_{args.datapoints}.json"

    windows = generate_dataset_and_windows(
        input_csv=input_csv,
        target_points=args.datapoints,
        output_csv=csv_5000,
        output_windows=windows_path,
        seed=args.seed,
    )

    train_models(windows=windows, model_dir=model_dir, random_state=args.seed)
    results = run_inference(windows=windows, model_dir=model_dir, output_scores=scores_path)
    enrichment_count = run_graph_phase(
        input_csv=csv_5000,
        scores_path=scores_path,
        graph_path=graph_path,
        enrichment_path=enrichment_path,
    )

    if len(results) != args.datapoints:
        raise RuntimeError(
            f"Inference output count mismatch: expected {args.datapoints}, got {len(results)}"
        )
    if enrichment_count != args.datapoints:
        raise RuntimeError(
            f"Graph enrichment count mismatch: expected {args.datapoints}, got {enrichment_count}"
        )

    high_risk = sum(1 for r in results if float(r["scores"]["final_risk"]) >= 70.0)
    print("Integrated phase run completed.")
    print(f"  datapoints: {args.datapoints}")
    print(f"  high-risk results: {high_risk}")
    print(f"  features: {windows_path}")
    print(f"  ml scores: {scores_path}")
    print(f"  graph: {graph_path}")
    print(f"  graph enrichment: {enrichment_path}")


if __name__ == "__main__":
    _cli()
