"""
ml/features.py — 60-second sliding window feature extraction pipeline.

Reads raw network flow records (CSV or dict list) and emits per-device
feature window payloads matching the Feature Window Contract in
docs/DATA_MODEL.md and docs/TEAM_EXECUTION_GUIDE.md §4.1.

Contract output shape:
    {
        "window_start": "<ISO-UTC>",
        "window_end":   "<ISO-UTC>",
        "device_id":    "<str>",
        "features": {
            "flow_duration_mean": float,
            "packet_rate":        float,
            "byte_volume":        float,
            "port_entropy":       float,
            "unique_dest_ips":    int,
            "tcp_ratio":          float,
            "udp_ratio":          float,
            "iat_mean":           float,
            "iat_std":            float,
        }
    }
"""
from __future__ import annotations

import csv
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

FlowRecord = dict[str, Any]
FeatureWindow = dict[str, Any]

# Feature keys as defined in the frozen contract (must not be renamed).
FEATURE_KEYS = (
    "flow_duration_mean",
    "packet_rate",
    "byte_volume",
    "port_entropy",
    "unique_dest_ips",
    "tcp_ratio",
    "udp_ratio",
    "iat_mean",
    "iat_std",
)

WINDOW_SECONDS = 60


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_float(value: str | float | None, default: float = 0.0) -> float:
    """Convert a value to float, returning *default* on failure."""
    if value is None:
        return default
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (ValueError, TypeError):
        return default


def _entropy(counts: dict[str, int]) -> float:
    """Shannon entropy over a frequency dict. Returns 0.0 for empty input."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )


def _std(values: list[float], mean: float) -> float:
    """Population standard deviation."""
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------

def extract_features(records: list[FlowRecord]) -> dict[str, float]:
    """
    Aggregate a list of raw flow records into a single feature vector.

    Each record may contain any subset of the raw fields below; missing
    fields are imputed with 0.0 / sensible defaults.

    Raw fields consumed (all optional, imputed if absent):
        flow_duration    — individual flow duration in seconds
        packet_rate      — packets/second for this flow
        byte_volume      — bytes transferred in this flow
        dest_ip          — destination IP address (string)
        dest_port        — destination port number
        protocol         — "tcp", "udp", or other
        iat              — inter-arrival time in seconds

    Pre-computed aggregates (used directly if present):
        flow_duration_mean, packet_rate, byte_volume, port_entropy,
        unique_dest_ips, tcp_ratio, udp_ratio, iat_mean, iat_std
    """
    if not records:
        return {k: 0.0 for k in FEATURE_KEYS}

    # Detect whether records are pre-aggregated (already have feature keys).
    # Require at least 6 of 9 keys to avoid false positives with raw flow records
    # that happen to share a key name (e.g. "packet_rate") with the feature schema.
    first = records[0]
    matching = sum(1 for k in FEATURE_KEYS if k in first)
    is_preaggregated = matching >= 6

    if is_preaggregated:
        return _aggregate_precomputed(records)
    return _aggregate_raw(records)


def _aggregate_precomputed(records: list[FlowRecord]) -> dict[str, float]:
    """Mean-pool pre-computed feature values across multiple records."""
    sums: dict[str, float] = {k: 0.0 for k in FEATURE_KEYS}
    counts: dict[str, int] = {k: 0 for k in FEATURE_KEYS}

    for rec in records:
        for key in FEATURE_KEYS:
            raw = rec.get(key)
            if raw is not None:
                sums[key] += _safe_float(raw)
                counts[key] += 1

    result: dict[str, float] = {}
    for key in FEATURE_KEYS:
        result[key] = (sums[key] / counts[key]) if counts[key] > 0 else 0.0
    return result


def _aggregate_raw(records: list[FlowRecord]) -> dict[str, float]:
    """Derive feature vector from raw per-flow records."""
    durations: list[float] = []
    packet_rates: list[float] = []
    total_bytes: float = 0.0
    dest_ips: set[str] = set()
    port_counts: dict[str, int] = {}
    tcp_count = 0
    udp_count = 0
    iats: list[float] = []

    for rec in records:
        dur = _safe_float(rec.get("flow_duration"))
        if dur > 0:
            durations.append(dur)

        pr = _safe_float(rec.get("packet_rate"))
        if pr > 0:
            packet_rates.append(pr)

        total_bytes += _safe_float(rec.get("byte_volume"))

        ip = str(rec.get("dest_ip", "")).strip()
        if ip:
            dest_ips.add(ip)

        port = str(rec.get("dest_port", "")).strip()
        if port:
            port_counts[port] = port_counts.get(port, 0) + 1

        proto = str(rec.get("protocol", "")).lower()
        if proto == "tcp":
            tcp_count += 1
        elif proto == "udp":
            udp_count += 1

        iat = _safe_float(rec.get("iat"))
        if iat > 0:
            iats.append(iat)

    dur_mean = (sum(durations) / len(durations)) if durations else 0.0
    pr_mean = (sum(packet_rates) / len(packet_rates)) if packet_rates else 0.0
    iat_mean = (sum(iats) / len(iats)) if iats else 0.0
    iat_std_val = _std(iats, iat_mean) if iats else 0.0
    proto_total = tcp_count + udp_count
    tcp_ratio = (tcp_count / proto_total) if proto_total > 0 else 0.0
    udp_ratio = (udp_count / proto_total) if proto_total > 0 else 0.0

    return {
        "flow_duration_mean": round(dur_mean, 6),
        "packet_rate":        round(pr_mean, 6),
        "byte_volume":        round(total_bytes, 2),
        "port_entropy":       round(_entropy(port_counts), 6),
        "unique_dest_ips":    float(len(dest_ips)),
        "tcp_ratio":          round(tcp_ratio, 6),
        "udp_ratio":          round(udp_ratio, 6),
        "iat_mean":           round(iat_mean, 6),
        "iat_std":            round(iat_std_val, 6),
    }


# ---------------------------------------------------------------------------
# Window builder
# ---------------------------------------------------------------------------

def _parse_timestamp(ts_str: str) -> datetime | None:
    """Parse ISO-8601 or epoch-second timestamps to UTC datetime."""
    if not ts_str:
        return None
    ts_str = ts_str.strip()
    # Try epoch float first
    try:
        epoch = float(ts_str)
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (ValueError, OSError):
        pass
    # Try ISO-8601
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def build_windows(
    records: list[FlowRecord],
    window_seconds: int = WINDOW_SECONDS,
    reference_start: datetime | None = None,
) -> list[FeatureWindow]:
    """
    Group flow records into fixed-duration windows per device and extract features.

    Args:
        records:          Raw or pre-aggregated flow records.
        window_seconds:   Window duration in seconds (default 60).
        reference_start:  Anchor for window alignment. If None, uses the
                          minimum timestamp in the data (or UTC now for
                          pre-aggregated records with no timestamp).

    Returns:
        List of FeatureWindow dicts matching the contract schema.
    """
    if not records:
        return []

    # Determine if records have timestamps
    has_timestamps = any(
        rec.get("timestamp") or rec.get("ts") or rec.get("time")
        for rec in records
    )

    if not has_timestamps:
        # Pre-aggregated / no-timestamp path: one window per device_id.
        by_device: dict[str, list[FlowRecord]] = {}
        for rec in records:
            dev = str(rec.get("device_id", "unknown")).strip()
            by_device.setdefault(dev, []).append(rec)

        base = reference_start or datetime.now(tz=timezone.utc).replace(
            second=0, microsecond=0
        )
        window_end = base + timedelta(seconds=window_seconds)
        w_start = base.strftime("%Y-%m-%dT%H:%M:%SZ")
        w_end = window_end.strftime("%Y-%m-%dT%H:%M:%SZ")

        results = []
        for dev, recs in by_device.items():
            features = extract_features(recs)
            results.append(
                {
                    "window_start": w_start,
                    "window_end":   w_end,
                    "device_id":    dev,
                    "features":     features,
                }
            )
        return results

    # Timestamp-aware path: bucket into fixed windows per device.
    by_device_ts: dict[str, list[tuple[datetime, FlowRecord]]] = {}
    min_ts: datetime | None = None

    for rec in records:
        raw_ts = rec.get("timestamp") or rec.get("ts") or rec.get("time") or ""
        ts = _parse_timestamp(str(raw_ts))
        if ts is None:
            ts = datetime.now(tz=timezone.utc)
        if min_ts is None or ts < min_ts:
            min_ts = ts
        dev = str(rec.get("device_id", "unknown")).strip()
        by_device_ts.setdefault(dev, []).append((ts, rec))

    anchor = reference_start or (min_ts or datetime.now(tz=timezone.utc))
    anchor = anchor.replace(second=0, microsecond=0)
    delta = timedelta(seconds=window_seconds)

    results = []
    for dev, ts_recs in by_device_ts.items():
        # Sort by timestamp
        ts_recs.sort(key=lambda x: x[0])

        # Group into buckets
        buckets: dict[int, list[FlowRecord]] = {}
        for ts, rec in ts_recs:
            bucket_idx = int((ts - anchor).total_seconds() // window_seconds)
            buckets.setdefault(bucket_idx, []).append(rec)

        for idx, recs in sorted(buckets.items()):
            w_start_dt = anchor + delta * idx
            w_end_dt = w_start_dt + delta
            features = extract_features(recs)
            results.append(
                {
                    "window_start": w_start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "window_end":   w_end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "device_id":    dev,
                    "features":     features,
                }
            )

    return results


# ---------------------------------------------------------------------------
# CSV loader
# ---------------------------------------------------------------------------

def load_csv(path: str | Path) -> list[FlowRecord]:
    """Load a CSV file into a list of FlowRecord dicts."""
    records: list[FlowRecord] = []
    with Path(path).open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            records.append(dict(row))
    return records


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Extract 60-second feature windows from flow data.")
    ap.add_argument("--input",  required=True, help="Input CSV file path.")
    ap.add_argument("--output", required=True, help="Output JSON file path.")
    ap.add_argument("--window", type=int, default=WINDOW_SECONDS, help="Window size in seconds.")
    args = ap.parse_args()

    records = load_csv(args.input)
    windows = build_windows(records, window_seconds=args.window)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"windows": windows}, indent=2), encoding="utf-8")
    print(f"Extracted {len(windows)} feature windows -> {out_path}")


if __name__ == "__main__":
    _cli()
