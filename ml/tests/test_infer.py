"""Unit tests for ml.infer — model-based inference module."""
from __future__ import annotations

import pickle
import tempfile
import unittest
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURE_KEYS
from ml.infer import ModelBundle, _confidence, _reason_codes_and_explanations, infer_window
from ml.score_window import ScoreResult


def _make_dummy_models(tmp_dir: Path) -> ModelBundle:
    """Create minimal trained artifacts in a temp dir and return a ModelBundle."""
    # 10 synthetic training samples with 9 features
    rng = np.random.default_rng(42)
    X = rng.random((10, len(FEATURE_KEYS)))

    scaler = StandardScaler().fit(X)
    X_sc = scaler.transform(X)

    iforest = IsolationForest(n_estimators=10, random_state=42).fit(X_sc)
    autoencoder = MLPRegressor(hidden_layer_sizes=(8,), max_iter=200, random_state=42).fit(X_sc, X_sc)
    ae_err = np.mean((X_sc - autoencoder.predict(X_sc)) ** 2, axis=1)
    ae_meta = {
        "error_mean": float(np.mean(ae_err)),
        "error_std": float(np.std(ae_err) or 1.0),
        "error_p95": float(np.percentile(ae_err, 95)),
    }
    classes = ["camera", "router", "sensor"]
    y = np.array([0, 1, 2, 0, 1, 2, 0, 1, 2, 0])
    dt_clf = RandomForestClassifier(n_estimators=10, random_state=42).fit(X_sc, y)

    for name, obj in [("scaler.pkl", scaler), ("isolation_forest.pkl", iforest),
                      ("autoencoder.pkl", autoencoder), ("autoencoder_meta.pkl", ae_meta),
                      ("device_classifier.pkl", dt_clf), ("device_classes.pkl", classes)]:
        with (tmp_dir / name).open("wb") as f:
            pickle.dump(obj, f)

    return ModelBundle(
        scaler=scaler,
        isolation_forest=iforest,
        isolation_forest_meta={
            "decision_mean": float(np.mean(iforest.decision_function(X_sc))),
            "decision_std": float(np.std(iforest.decision_function(X_sc)) or 1.0),
            "decision_p05": float(np.percentile(iforest.decision_function(X_sc), 5)),
            "decision_p95": float(np.percentile(iforest.decision_function(X_sc), 95)),
            "threshold_offset": float(getattr(iforest, "offset_", 0.0)),
        },
        device_classifier=dt_clf,
        device_classes=classes,
        autoencoder=autoencoder,
        autoencoder_meta=ae_meta,
    )


SAMPLE_FEATURES = {
    "flow_duration_mean": 1.24, "packet_rate": 52.1, "byte_volume": 81234.0,
    "port_entropy": 2.18, "unique_dest_ips": 9.0, "tcp_ratio": 0.64,
    "udp_ratio": 0.35, "iat_mean": 0.092, "iat_std": 0.031,
}


class TestInferWindow(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.models = _make_dummy_models(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_returns_score_result(self):
        result = infer_window(self.models, device_id="cam-001", device_type="camera",
                              features=SAMPLE_FEATURES)
        self.assertIsInstance(result, ScoreResult)

    def test_contract_fields_present(self):
        result = infer_window(self.models, device_id="cam-001", device_type="camera",
                              features=SAMPLE_FEATURES)
        payload = result.to_contract_payload()
        for key in ("timestamp", "device_id", "device_type", "scores", "reason_codes", "explanations"):
            self.assertIn(key, payload)
        self.assertIn("autoencoder", payload["scores"])

    def test_risk_within_bounds(self):
        result = infer_window(self.models, device_id="cam-001", device_type="camera",
                              features=SAMPLE_FEATURES)
        self.assertGreaterEqual(result.final_risk, 0.0)
        self.assertLessEqual(result.final_risk, 100.0)

    def test_timestamp_preserved(self):
        ts = "2026-03-12T09:01:00Z"
        result = infer_window(self.models, device_id="x", device_type="t",
                              features=SAMPLE_FEATURES, timestamp=ts)
        self.assertEqual(result.timestamp, ts)

    def test_deterministic_for_same_input(self):
        ts = "2026-03-12T09:01:00Z"
        r1 = infer_window(self.models, device_id="cam-001", device_type="camera",
                          features=SAMPLE_FEATURES, timestamp=ts)
        r2 = infer_window(self.models, device_id="cam-001", device_type="camera",
                          features=SAMPLE_FEATURES, timestamp=ts)
        self.assertEqual(r1, r2)

    def test_inference_under_150ms(self):
        """Handoff acceptance criterion: inference < 150ms."""
        import time
        start = time.perf_counter()
        infer_window(self.models, device_id="cam-001", device_type="camera",
                     features=SAMPLE_FEATURES)
        elapsed_ms = (time.perf_counter() - start) * 1000
        self.assertLess(elapsed_ms, 150, f"Inference took {elapsed_ms:.1f}ms — exceeds 150ms limit")

    def test_no_classifier_fallback(self):
        """ModelBundle with no classifier still works (fallback to provided device_type)."""
        bundle_no_clf = ModelBundle(
            scaler=self.models.scaler,
            isolation_forest=self.models.isolation_forest,
            isolation_forest_meta=self.models.isolation_forest_meta,
            device_classifier=None,
            device_classes=[],
            autoencoder=self.models.autoencoder,
            autoencoder_meta=self.models.autoencoder_meta,
        )
        result = infer_window(bundle_no_clf, device_id="x", device_type="camera",
                              features=SAMPLE_FEATURES)
        self.assertEqual(result.device_type, "camera")

    def test_weighted_fusion_uses_autoencoder(self):
        result = infer_window(self.models, device_id="cam-001", device_type="camera", features=SAMPLE_FEATURES)
        self.assertIsNotNone(result.autoencoder)
        assert result.autoencoder is not None
        expected = np.clip(0.7 * result.isolation_forest + 0.3 * result.autoencoder, 0.0, 100.0)
        self.assertAlmostEqual(result.final_risk, float(expected), places=6)


class TestConfidence(unittest.TestCase):
    def test_high(self):    self.assertEqual(_confidence(80.0), "high")
    def test_medium(self):  self.assertEqual(_confidence(65.0), "medium")
    def test_low(self):     self.assertEqual(_confidence(30.0), "low")
    def test_boundary(self):
        self.assertEqual(_confidence(50.0), "medium")
        self.assertEqual(_confidence(80.0), "high")
        self.assertEqual(_confidence(49.9), "low")


class TestReasonCodes(unittest.TestCase):
    def test_high_risk_produces_explanations(self):
        codes, exps = _reason_codes_and_explanations(
            ModelBundle(None, None, None, None, [], None, None),
            np.zeros((1, len(FEATURE_KEYS))),
            {"byte_volume": 90000, "packet_rate": 55, "unique_dest_ips": 10,
             "port_entropy": 2.5, "udp_ratio": 0.2}, risk=85.0
        )
        self.assertGreater(len(codes), 0)
        self.assertGreater(len(exps), 0)

    def test_low_risk_no_explanations(self):
        codes, exps = _reason_codes_and_explanations(
            ModelBundle(None, None, None, None, [], None, None),
            np.zeros((1, len(FEATURE_KEYS))),
            {"byte_volume": 1000, "packet_rate": 5}, risk=30.0
        )
        self.assertEqual(codes, [])
        self.assertEqual(exps, [])

    def test_high_risk_at_least_two_explanations(self):
        """Handoff acceptance criterion: ≥2 explanation strings for high-risk."""
        codes, exps = _reason_codes_and_explanations(
            ModelBundle(None, None, None, None, [], None, None),
            np.zeros((1, len(FEATURE_KEYS))),
            {"byte_volume": 200000, "packet_rate": 100, "unique_dest_ips": 20,
             "port_entropy": 3.5, "udp_ratio": 0.1}, risk=90.0
        )
        self.assertGreaterEqual(len(exps), 2)


if __name__ == "__main__":
    unittest.main()
