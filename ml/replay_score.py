from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from ml.score_window import score_features


def _to_float(x: str | None) -> float | None:
    if x is None:
        return None
    s = str(x).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="CSV with at least device_id and numeric columns.")
    ap.add_argument("--output", required=True, help="Output JSON file path (anomaly result items).")
    ap.add_argument("--device-type", default="unknown", help="Fallback device_type if not in input.")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    items: list[dict] = []

    with in_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "device_id" not in reader.fieldnames:
            raise ValueError("Input CSV must include a 'device_id' column.")

        rows_by_device: dict[str, list[dict[str, str]]] = {}
        for row in reader:
            device_id = (row.get("device_id") or "").strip()
            if not device_id:
                continue
            rows_by_device.setdefault(device_id, []).append(row)

    for device_id, rows in rows_by_device.items():
        device_type = args.device_type
        for r in rows:
            dt = (r.get("device_type") or "").strip()
            if dt:
                device_type = dt
                break

        # Mean of numeric columns (excluding device_id/device_type).
        sums: dict[str, float] = {}
        counts: dict[str, int] = {}
        for r in rows:
            for k, v in r.items():
                if k in ("device_id", "device_type") or k is None:
                    continue
                fv = _to_float(v)
                if fv is None:
                    continue
                sums[k] = sums.get(k, 0.0) + fv
                counts[k] = counts.get(k, 0) + 1

        features = {k: (sums[k] / counts[k]) for k in sums if counts.get(k, 0) > 0}
        result = score_features(device_id=device_id, device_type=device_type, features=features)
        items.append(result.to_contract_payload())

    out = {"items": items}
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote {len(items)} anomaly results to {out_path}")


if __name__ == "__main__":
    main()

