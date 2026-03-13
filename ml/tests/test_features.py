"""Unit tests for ml.features — feature extraction pipeline."""
from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from ml.features import (
    FEATURE_KEYS,
    _entropy,
    _std,
    build_windows,
    extract_features,
    load_csv,
)


class TestExtractFeatures(unittest.TestCase):
    """Tests for extract_features() with pre-aggregated records."""

    SAMPLE = {
        "flow_duration_mean": "1.24",
        "packet_rate": "52.1",
        "byte_volume": "81234",
        "port_entropy": "2.18",
        "unique_dest_ips": "9",
        "tcp_ratio": "0.64",
        "udp_ratio": "0.35",
        "iat_mean": "0.092",
        "iat_std": "0.031",
    }

    def test_returns_all_feature_keys(self):
        result = extract_features([self.SAMPLE])
        for key in FEATURE_KEYS:
            self.assertIn(key, result, f"Missing feature key: {key}")

    def test_values_are_floats(self):
        result = extract_features([self.SAMPLE])
        for k, v in result.items():
            self.assertIsInstance(v, float, f"Non-float value for {k}: {v}")

    def test_empty_records_returns_zeros(self):
        result = extract_features([])
        for key in FEATURE_KEYS:
            self.assertEqual(result[key], 0.0)

    def test_averaging_multiple_records(self):
        r1 = dict(self.SAMPLE, byte_volume="100")
        r2 = dict(self.SAMPLE, byte_volume="200")
        result = extract_features([r1, r2])
        self.assertAlmostEqual(result["byte_volume"], 150.0, places=1)

    def test_missing_keys_default_to_zero(self):
        result = extract_features([{"device_id": "x"}])
        for key in FEATURE_KEYS:
            self.assertEqual(result[key], 0.0)

    def test_raw_flow_records(self):
        """Records without feature keys are treated as raw flows."""
        raw = [
            {"flow_duration": "1.0", "packet_rate": "10", "byte_volume": "5000",
             "dest_ip": "1.2.3.4", "dest_port": "443", "protocol": "tcp", "iat": "0.1"},
            {"flow_duration": "2.0", "packet_rate": "20", "byte_volume": "8000",
             "dest_ip": "5.6.7.8", "dest_port": "80",  "protocol": "udp", "iat": "0.2"},
        ]
        result = extract_features(raw)
        self.assertGreater(result["byte_volume"], 0)
        self.assertEqual(result["unique_dest_ips"], 2.0)
        self.assertAlmostEqual(result["tcp_ratio"], 0.5)
        self.assertAlmostEqual(result["udp_ratio"], 0.5)


class TestBuildWindows(unittest.TestCase):
    """Tests for build_windows()."""

    RECORDS = [
        {"device_id": "cam-001", "device_type": "camera",
         "byte_volume": "81234", "packet_rate": "52.1", "unique_dest_ips": "9",
         "port_entropy": "2.18", "flow_duration_mean": "1.24",
         "tcp_ratio": "0.64", "udp_ratio": "0.35", "iat_mean": "0.092", "iat_std": "0.031"},
        {"device_id": "sensor-07", "device_type": "sensor",
         "byte_volume": "1200", "packet_rate": "3.1", "unique_dest_ips": "1",
         "port_entropy": "0.10", "flow_duration_mean": "0.45",
         "tcp_ratio": "0.90", "udp_ratio": "0.10", "iat_mean": "0.310", "iat_std": "0.004"},
    ]

    def test_one_window_per_device(self):
        windows = build_windows(self.RECORDS)
        device_ids = [w["device_id"] for w in windows]
        self.assertIn("cam-001", device_ids)
        self.assertIn("sensor-07", device_ids)
        self.assertEqual(len(windows), 2)

    def test_window_has_required_keys(self):
        windows = build_windows(self.RECORDS)
        for w in windows:
            for key in ("window_start", "window_end", "device_id", "features"):
                self.assertIn(key, w)

    def test_features_have_all_keys(self):
        windows = build_windows(self.RECORDS)
        for w in windows:
            for k in FEATURE_KEYS:
                self.assertIn(k, w["features"])

    def test_window_timestamps_are_strings(self):
        windows = build_windows(self.RECORDS)
        for w in windows:
            self.assertIsInstance(w["window_start"], str)
            self.assertIsInstance(w["window_end"], str)

    def test_empty_input(self):
        windows = build_windows([])
        self.assertEqual(windows, [])

    def test_timestamp_bucketing(self):
        """Records with timestamps should be bucketed into correct windows."""
        ts_records = [
            {"device_id": "x", "timestamp": "2026-03-12T09:00:30",
             "byte_volume": "1000", "packet_rate": "5", "unique_dest_ips": "1",
             "port_entropy": "0.5", "flow_duration_mean": "0.5",
             "tcp_ratio": "1.0", "udp_ratio": "0.0", "iat_mean": "0.1", "iat_std": "0.01"},
            {"device_id": "x", "timestamp": "2026-03-12T09:01:30",
             "byte_volume": "2000", "packet_rate": "10", "unique_dest_ips": "2",
             "port_entropy": "1.0", "flow_duration_mean": "0.5",
             "tcp_ratio": "1.0", "udp_ratio": "0.0", "iat_mean": "0.1", "iat_std": "0.01"},
        ]
        windows = build_windows(ts_records, window_seconds=60)
        # Should produce 2 windows (each record falls in a different 60-second bucket)
        self.assertEqual(len(windows), 2)


class TestLoadCsv(unittest.TestCase):
    def test_loads_rows(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.csv"
            with p.open("w", newline="") as f:
                csv.writer(f).writerows([
                    ["device_id", "byte_volume"],
                    ["cam-001", "5000"],
                ])
            records = load_csv(p)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["device_id"], "cam-001")


class TestHelpers(unittest.TestCase):
    def test_entropy_uniform(self):
        counts = {"a": 1, "b": 1, "c": 1, "d": 1}
        self.assertAlmostEqual(_entropy(counts), 2.0, places=5)

    def test_entropy_single(self):
        self.assertEqual(_entropy({"a": 1}), 0.0)

    def test_entropy_empty(self):
        self.assertEqual(_entropy({}), 0.0)

    def test_std_population(self):
        vals = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        mean = sum(vals) / len(vals)
        result = _std(vals, mean)
        self.assertAlmostEqual(result, 2.0, places=5)

    def test_std_single(self):
        self.assertEqual(_std([5.0], 5.0), 0.0)


class TestCliFeatures(unittest.TestCase):
    """Integration test: CLI writes valid JSON."""

    def test_cli_produces_valid_json(self):
        import sys
        old_argv = sys.argv
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / "in.csv"
            out = Path(td) / "out.json"
            with inp.open("w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["device_id", "byte_volume", "packet_rate", "unique_dest_ips",
                             "port_entropy", "flow_duration_mean", "tcp_ratio", "udp_ratio",
                             "iat_mean", "iat_std"])
                w.writerow(["cam-001", "81234", "52.1", "9", "2.18", "1.24", "0.64", "0.35", "0.092", "0.031"])

            try:
                sys.argv = ["ml.features", "--input", str(inp), "--output", str(out)]
                from ml.features import _cli
                _cli()
            finally:
                sys.argv = old_argv

            data = json.loads(out.read_text())
        self.assertIn("windows", data)
        self.assertEqual(len(data["windows"]), 1)
        self.assertIn("features", data["windows"][0])


if __name__ == "__main__":
    unittest.main()
