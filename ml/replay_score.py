from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.features import build_windows, load_csv
from ml.infer import infer_window, load_models
from ml.score_window import score_features


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="CSV with at least device_id and numeric columns.")
    ap.add_argument("--output", required=True, help="Output JSON file path (anomaly result items).")
    ap.add_argument("--device-type", default="unknown", help="Fallback device_type if not in input.")
    ap.add_argument("--model-dir", default="artifacts/models", help="Directory containing trained model artifacts.")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    records = load_csv(in_path)
    if not records:
        out = {"items": []}
        out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print("Input CSV has no data rows. Wrote empty items list.")
        return

    device_type_map: dict[str, str] = {}
    for rec in records:
        device_id = str(rec.get("device_id", "")).strip()
        device_type = str(rec.get("device_type", "")).strip()
        if device_id and device_type:
            device_type_map[device_id] = device_type

    windows = build_windows(records)
    for window in windows:
        window["device_type"] = device_type_map.get(window.get("device_id", ""), args.device_type)

    items: list[dict] = []
    try:
        models = load_models(args.model_dir)
    except Exception as exc:
        print(f"Could not load trained models from {args.model_dir} ({exc}); falling back to heuristic scoring.")
        models = None

    if models is not None:
        best_by_device: dict[str, object] = {}
        for window in windows:
            device_id = str(window.get("device_id", "unknown"))
            result = infer_window(
                models,
                device_id=device_id,
                device_type=str(window.get("device_type", args.device_type)),
                features=window.get("features", {}),
                timestamp=str(window.get("window_end", "")) or None,
            )
            prev = best_by_device.get(device_id)
            if prev is None or result.final_risk > prev.final_risk:
                best_by_device[device_id] = result

        items = [best_by_device[device_id].to_contract_payload() for device_id in sorted(best_by_device)]
    else:
        feature_means_by_device: dict[str, list[dict[str, float]]] = {}
        for window in windows:
            device_id = str(window.get("device_id", "unknown"))
            feature_means_by_device.setdefault(device_id, []).append(window.get("features", {}))

        for device_id, feature_windows in sorted(feature_means_by_device.items()):
            feature_keys = set().union(*(features.keys() for features in feature_windows))
            features = {
                key: sum(float(features.get(key, 0.0)) for features in feature_windows) / len(feature_windows)
                for key in feature_keys
            }
            result = score_features(
                device_id=device_id,
                device_type=device_type_map.get(device_id, args.device_type),
                features=features,
            )
            items.append(result.to_contract_payload())

    out = {"items": items}
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote {len(items)} anomaly results to {out_path}")


if __name__ == "__main__":
    main()

