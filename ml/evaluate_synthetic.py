from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def load_ground_truth_devices(csv_path: Path) -> tuple[set[str], dict[str, list[str]]]:
    compromised_devices: set[str] = set()
    stages_by_device: dict[str, set[str]] = {}

    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            device_id = (row.get("device_id") or row.get("src_device") or "").strip()
            if not device_id:
                continue
            if str(row.get("is_attack", "0")).strip() == "1":
                compromised_devices.add(device_id)
                stage = (row.get("attack_stage") or "").strip()
                if stage:
                    stages_by_device.setdefault(device_id, set()).add(stage)

    return compromised_devices, {k: sorted(v) for k, v in stages_by_device.items()}


def load_predictions(scores_path: Path, threshold: float) -> tuple[set[str], dict[str, float]]:
    data = json.loads(scores_path.read_text(encoding="utf-8"))
    items = data.get("items", [])
    predicted: set[str] = set()
    scores: dict[str, float] = {}

    for item in items:
        device_id = str(item.get("device_id", "")).strip()
        final_risk = float(item.get("scores", {}).get("final_risk", 0.0) or 0.0)
        if not device_id:
            continue
        scores[device_id] = final_risk
        if final_risk >= threshold:
            predicted.add(device_id)

    return predicted, scores


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate device-level synthetic anomaly results.")
    parser.add_argument("--dataset", required=True, help="Synthetic CSV with label columns.")
    parser.add_argument("--scores", required=True, help="JSON produced by ml.replay_score.")
    parser.add_argument("--threshold", type=float, default=70.0, help="Risk threshold for positive anomaly detection.")
    parser.add_argument(
        "--sweep",
        action="store_true",
        help="Sweep thresholds 50–80 and print precision/recall/F1 table to find the best operating point.",
    )
    args = parser.parse_args()

    gt_devices, stages_by_device = load_ground_truth_devices(Path(args.dataset))
    _, all_scores = load_predictions(Path(args.scores), threshold=0.0)  # load all scores

    if args.sweep:
        print(f"{'threshold':>10}  {'tp':>4}  {'fp':>4}  {'fn':>4}  {'precision':>10}  {'recall':>8}  {'f1':>8}")
        print("-" * 65)
        best_f1, best_thresh = 0.0, args.threshold
        for t in range(50, 81):
            thresh = float(t)
            pred_sweep = {d for d, s in all_scores.items() if s >= thresh}
            tp_s = gt_devices & pred_sweep
            fp_s = pred_sweep - gt_devices
            fn_s = gt_devices - pred_sweep
            prec = len(tp_s) / len(pred_sweep) if pred_sweep else 0.0
            rec  = len(tp_s) / len(gt_devices) if gt_devices else 0.0
            f1   = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
            marker = " ← best" if f1 > best_f1 else ""
            if f1 > best_f1:
                best_f1, best_thresh = f1, thresh
            print(f"  {thresh:>8.1f}  {len(tp_s):>4}  {len(fp_s):>4}  {len(fn_s):>4}  {prec:>10.3f}  {rec:>8.3f}  {f1:>8.3f}{marker}")
        print(f"\nBest F1={best_f1:.3f} at threshold={best_thresh:.1f}")
        return

    pred_devices, scores = load_predictions(Path(args.scores), args.threshold)

    all_devices = sorted(set(scores) | gt_devices)
    tp = sorted(gt_devices & pred_devices)
    fp = sorted(pred_devices - gt_devices)
    fn = sorted(gt_devices - pred_devices)
    tn = sorted(set(all_devices) - set(tp) - set(fp) - set(fn))

    precision = len(tp) / len(pred_devices) if pred_devices else 0.0
    recall = len(tp) / len(gt_devices) if gt_devices else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print(f"threshold={args.threshold:.1f}")
    print(f"devices_total={len(all_devices)} compromised_gt={len(gt_devices)} predicted_positive={len(pred_devices)}")
    print(f"tp={len(tp)} fp={len(fp)} fn={len(fn)} tn={len(tn)}")
    print(f"precision={precision:.3f} recall={recall:.3f} f1={f1:.3f}")
    print("details:")
    for device_id in all_devices:
        gt = "attack" if device_id in gt_devices else "benign"
        pred = "attack" if device_id in pred_devices else "benign"
        score = scores.get(device_id, 0.0)
        stages = ",".join(stages_by_device.get(device_id, []))
        print(f"  {device_id}: gt={gt} pred={pred} risk={score:.1f} stages={stages}")


if __name__ == "__main__":
    main()
