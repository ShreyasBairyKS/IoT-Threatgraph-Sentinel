"""Unit tests for ml.replay_score module."""
from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path


class TestReplayScore(unittest.TestCase):
    """Tests for the replay_score CLI pipeline."""

    HEADERS = [
        "device_id", "device_type", "flow_duration_mean", "packet_rate",
        "byte_volume", "port_entropy", "unique_dest_ips", "tcp_ratio",
        "udp_ratio", "iat_mean", "iat_std",
    ]

    ROWS = [
        ["cam-001", "camera", "1.24", "52.1", "81234", "2.18", "9", "0.64", "0.35", "0.092", "0.031"],
        ["cam-001", "camera", "1.18", "49.8", "79210", "2.05", "8", "0.66", "0.33", "0.098", "0.029"],
        ["sensor-07", "sensor", "0.45", "3.1", "1200", "0.10", "1", "0.90", "0.10", "0.310", "0.004"],
    ]

    def _write_csv(self, path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(self.HEADERS)
            writer.writerows(self.ROWS)

    def _run_replay(self, input_path: Path, output_path: Path) -> dict:
        """Import and invoke main() programmatically with patched argv."""
        import sys
        old_argv = sys.argv
        try:
            sys.argv = [
                "replay_score",
                "--input", str(input_path),
                "--output", str(output_path),
            ]
            from ml.replay_score import main
            main()
        finally:
            sys.argv = old_argv

        return json.loads(output_path.read_text(encoding="utf-8"))

    def test_produces_valid_json_output(self):
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / "flows.csv"
            out = Path(td) / "scores.json"
            self._write_csv(inp)
            data = self._run_replay(inp, out)
            self.assertIn("items", data)
            self.assertIsInstance(data["items"], list)

    def test_one_result_per_device(self):
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / "flows.csv"
            out = Path(td) / "scores.json"
            self._write_csv(inp)
            data = self._run_replay(inp, out)
            device_ids = [item["device_id"] for item in data["items"]]
            self.assertEqual(len(device_ids), 2)  # cam-001, sensor-07
            self.assertIn("cam-001", device_ids)
            self.assertIn("sensor-07", device_ids)

    def test_output_has_contract_fields(self):
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / "flows.csv"
            out = Path(td) / "scores.json"
            self._write_csv(inp)
            data = self._run_replay(inp, out)
            for item in data["items"]:
                for key in ("timestamp", "device_id", "device_type", "scores", "reason_codes", "explanations"):
                    self.assertIn(key, item, f"Missing contract field: {key}")
                for skey in ("isolation_forest", "final_risk", "confidence"):
                    self.assertIn(skey, item["scores"], f"Missing scores field: {skey}")

    def test_empty_csv_produces_empty_items(self):
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / "empty.csv"
            out = Path(td) / "scores.json"
            with inp.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(self.HEADERS)  # header only, no data rows
            data = self._run_replay(inp, out)
            self.assertEqual(data["items"], [])

    def test_risk_scores_within_bounds(self):
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / "flows.csv"
            out = Path(td) / "scores.json"
            self._write_csv(inp)
            data = self._run_replay(inp, out)
            for item in data["items"]:
                risk = item["scores"]["final_risk"]
                self.assertGreaterEqual(risk, 0.0)
                self.assertLessEqual(risk, 100.0)


if __name__ == "__main__":
    unittest.main()
