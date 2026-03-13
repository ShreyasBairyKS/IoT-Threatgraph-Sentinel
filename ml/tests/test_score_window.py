"""Unit tests for ml.score_window module."""
from __future__ import annotations

import json
import unittest

from ml.score_window import ScoreResult, score_features


class TestScoreResult(unittest.TestCase):
    """Tests for the ScoreResult dataclass and serialisation."""

    def _make_result(self, **overrides):
        defaults = dict(
            timestamp="2026-03-12T09:01:00Z",
            device_id="cam-001",
            device_type="camera",
            isolation_forest=78.4,
            autoencoder=64.2,
            final_risk=73.1,
            confidence="high",
            reason_codes=["outbound_volume_spike"],
            explanations=["Outbound traffic is above rolling baseline"],
        )
        defaults.update(overrides)
        return ScoreResult(**defaults)

    def test_required_fields_present_in_payload(self):
        result = self._make_result()
        payload = result.to_contract_payload()
        for key in ("timestamp", "device_id", "device_type", "scores", "reason_codes", "explanations"):
            self.assertIn(key, payload, f"Missing required field: {key}")

    def test_scores_subfields(self):
        payload = self._make_result().to_contract_payload()
        scores = payload["scores"]
        self.assertIn("isolation_forest", scores)
        self.assertIn("final_risk", scores)
        self.assertIn("confidence", scores)

    def test_autoencoder_omitted_when_none(self):
        payload = self._make_result(autoencoder=None).to_contract_payload()
        self.assertNotIn("autoencoder", payload["scores"])

    def test_autoencoder_included_when_present(self):
        payload = self._make_result(autoencoder=64.2).to_contract_payload()
        self.assertIn("autoencoder", payload["scores"])
        self.assertAlmostEqual(payload["scores"]["autoencoder"], 64.2)

    def test_payload_is_json_serialisable(self):
        payload = self._make_result().to_contract_payload()
        try:
            json.dumps(payload)
        except (TypeError, ValueError) as exc:
            self.fail(f"Payload is not JSON-serialisable: {exc}")

    def test_frozen_dataclass(self):
        result = self._make_result()
        with self.assertRaises(AttributeError):
            result.device_id = "other"  # type: ignore[misc]


class TestScoreFeatures(unittest.TestCase):
    """Tests for the score_features heuristic scorer."""

    SAMPLE_FEATURES = {
        "flow_duration_mean": 1.24,
        "packet_rate": 52.1,
        "byte_volume": 81234,
        "port_entropy": 2.18,
        "unique_dest_ips": 9,
        "tcp_ratio": 0.64,
        "udp_ratio": 0.35,
        "iat_mean": 0.092,
        "iat_std": 0.031,
    }

    def test_returns_score_result(self):
        result = score_features(
            device_id="cam-001",
            device_type="camera",
            features=self.SAMPLE_FEATURES,
        )
        self.assertIsInstance(result, ScoreResult)

    def test_contract_fields_populated(self):
        result = score_features(
            device_id="cam-001",
            device_type="camera",
            features=self.SAMPLE_FEATURES,
        )
        self.assertEqual(result.device_id, "cam-001")
        self.assertEqual(result.device_type, "camera")
        self.assertIsInstance(result.final_risk, float)
        self.assertIn(result.confidence, ("low", "medium", "high"))

    def test_risk_within_bounds(self):
        result = score_features(
            device_id="cam-001",
            device_type="camera",
            features=self.SAMPLE_FEATURES,
        )
        self.assertGreaterEqual(result.final_risk, 0.0)
        self.assertLessEqual(result.final_risk, 100.0)

    def test_custom_timestamp_preserved(self):
        ts = "2026-03-11T10:00:00Z"
        result = score_features(
            device_id="cam-001",
            device_type="camera",
            features=self.SAMPLE_FEATURES,
            timestamp=ts,
        )
        self.assertEqual(result.timestamp, ts)

    def test_high_risk_produces_explanations(self):
        """High byte_volume + unique_dest_ips should produce risk >= 70 and explanations."""
        high_features = {
            "byte_volume": 200000,
            "packet_rate": 100,
            "unique_dest_ips": 20,
            "port_entropy": 3.5,
        }
        result = score_features(
            device_id="cam-001",
            device_type="camera",
            features=high_features,
        )
        self.assertGreaterEqual(result.final_risk, 70)
        self.assertGreater(len(result.explanations), 0)
        self.assertGreater(len(result.reason_codes), 0)

    def test_low_traffic_produces_low_risk(self):
        low_features = {
            "byte_volume": 100,
            "packet_rate": 1.0,
            "unique_dest_ips": 1,
            "port_entropy": 0.1,
        }
        result = score_features(
            device_id="sensor-07",
            device_type="sensor",
            features=low_features,
        )
        self.assertLess(result.final_risk, 70)

    def test_empty_features_no_crash(self):
        result = score_features(
            device_id="unknown-01",
            device_type="unknown",
            features={},
        )
        self.assertEqual(result.final_risk, 0.0)

    def test_deterministic_scoring(self):
        """Same input must produce same output (handoff acceptance criterion)."""
        r1 = score_features(
            device_id="cam-001",
            device_type="camera",
            features=self.SAMPLE_FEATURES,
            timestamp="2026-03-12T09:01:00Z",
        )
        r2 = score_features(
            device_id="cam-001",
            device_type="camera",
            features=self.SAMPLE_FEATURES,
            timestamp="2026-03-12T09:01:00Z",
        )
        self.assertEqual(r1, r2)

    def test_confidence_thresholds(self):
        """Verify the confidence mapping: >=80 high, >=50 medium, else low."""
        # Force a known score by providing extreme features
        # Very high → should be "high"
        high = score_features(
            device_id="x", device_type="t",
            features={"byte_volume": 999999, "packet_rate": 200, "unique_dest_ips": 30, "port_entropy": 4.0},
        )
        self.assertEqual(high.confidence, "high")

        # Zero → should be "low"
        low = score_features(
            device_id="x", device_type="t",
            features={"byte_volume": 0, "packet_rate": 0, "unique_dest_ips": 0, "port_entropy": 0},
        )
        self.assertEqual(low.confidence, "low")


class TestSchemaCompliance(unittest.TestCase):
    """Validate output against the JSON Schema in artifacts/schemas/."""

    def test_payload_matches_anomaly_result_schema(self):
        """Structural check mirroring anomaly_result.schema.json."""
        result = score_features(
            device_id="cam-001",
            device_type="camera",
            features={"byte_volume": 81234, "packet_rate": 52.1, "unique_dest_ips": 9, "port_entropy": 2.18},
            timestamp="2026-03-12T09:01:00Z",
        )
        payload = result.to_contract_payload()

        # Top-level required keys
        for key in ("timestamp", "device_id", "device_type", "scores", "reason_codes", "explanations"):
            self.assertIn(key, payload)

        # Scores sub-object required keys
        for key in ("isolation_forest", "final_risk", "confidence"):
            self.assertIn(key, payload["scores"])

        # Type checks
        self.assertIsInstance(payload["timestamp"], str)
        self.assertIsInstance(payload["device_id"], str)
        self.assertIsInstance(payload["scores"]["final_risk"], float)
        self.assertIn(payload["scores"]["confidence"], ("low", "medium", "high"))
        self.assertIsInstance(payload["reason_codes"], list)
        self.assertIsInstance(payload["explanations"], list)

        # Range check
        self.assertGreaterEqual(payload["scores"]["final_risk"], 0)
        self.assertLessEqual(payload["scores"]["final_risk"], 100)


if __name__ == "__main__":
    unittest.main()
