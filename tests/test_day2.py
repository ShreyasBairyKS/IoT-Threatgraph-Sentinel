"""
tests/test_day2.py - Day 2 ingestion pipeline and report tests.

Covers:
  1. Ingestion endpoints (POST /ingest/anomaly + /ingest/graph) accept valid payloads.
  2. Ingestion of high-risk anomaly populates the alert store (reflected in GET /alerts).
  3. Ingestion of low-risk anomaly does NOT create an alert.
  4. Graph enrichment updates the graph store (reflected in GET /graph).
  5. POST /report uses the real build_report() (not the mock).
  6. GET /report/{event_id}/pdf returns 200 + PDF bytes for a stored alert.
  7. GET /report/{event_id}/pdf returns 404 for an unknown event_id.
  8. Alert merger: build_alert_event() builds correct AlertEvent from AnomalyResult + graph.
  9. Device registry updated after anomaly ingestion.

Run: pytest tests/ -v
"""

import asyncio
import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone

from backend.main import app
from backend.contracts import (
    AlertEvent,
    AnomalyResult,
    AnomalyScores,
    GraphEnrichment,
    IncidentReport,
    MITRETag,
    NextTargetPrediction,
)
from backend.store import (
    alert_store,
    device_registry,
    graph_store,
    build_alert_event,
    ALERT_RISK_THRESHOLD,
)
from backend.mocks.mock_store import MOCK_ALERTS

client = TestClient(app)

_NOW = datetime(2026, 3, 13, 6, 0, 0, tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

VALID_ANOMALY_HIGH = {
    "timestamp": _NOW.isoformat(),
    "device_id": "cam-002",
    "device_type": "camera",
    "scores": {
        "isolation_forest": 82.0,
        "autoencoder": 79.0,
        "final_risk": 81.0,
        "confidence": "high",
    },
    "reason_codes": ["outbound_volume_spike"],
    "explanations": ["Outbound traffic is 5x above baseline", "New external IPs contacted"],
}

VALID_ANOMALY_LOW = {
    "timestamp": _NOW.isoformat(),
    "device_id": "sensor-02",
    "device_type": "sensor",
    "scores": {
        "isolation_forest": 20.0,
        "autoencoder": 18.0,
        "final_risk": 19.0,
        "confidence": "low",
    },
    "reason_codes": [],
    "explanations": [],
}

VALID_GRAPH = {
    "timestamp": _NOW.isoformat(),
    "source_device": "cam-002",
    "propagation_risk": 0.72,
    "neighbors": ["router-02", "sensor-02"],
    "next_target_prediction": [
        {"device_id": "router-02", "score": 0.85, "why": "high betweenness centrality"}
    ],
    "attack_paths": [["cam-002", "router-02", "firewall-01"]],
    "mitre": {"tactic": "Lateral Movement", "technique": "T1021"},
}


# ---------------------------------------------------------------------------
# 1. Ingestion endpoints accept valid payloads
# ---------------------------------------------------------------------------

class TestIngestEndpoints:
    def test_ingest_anomaly_accepts_high_risk(self):
        r = client.post("/ingest/anomaly", json=VALID_ANOMALY_HIGH)
        assert r.status_code == 202
        assert r.json()["status"] == "accepted"
        assert r.json()["device_id"] == "cam-002"

    def test_ingest_anomaly_accepts_low_risk(self):
        r = client.post("/ingest/anomaly", json=VALID_ANOMALY_LOW)
        assert r.status_code == 202

    def test_ingest_graph_accepts_valid_payload(self):
        r = client.post("/ingest/graph", json=VALID_GRAPH)
        assert r.status_code == 202
        assert r.json()["status"] == "accepted"
        assert r.json()["source_device"] == "cam-002"

    def test_ingest_anomaly_rejects_malformed(self):
        r = client.post("/ingest/anomaly", json={"bad": "data"})
        assert r.status_code == 422

    def test_ingest_graph_rejects_malformed(self):
        r = client.post("/ingest/graph", json={"missing": "fields"})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# 2. Store integration: high-risk anomaly → alert in store via GET /alerts
# ---------------------------------------------------------------------------

class TestStoreIntegration:
    def test_graph_store_updated_after_ingest(self):
        client.post("/ingest/graph", json=VALID_GRAPH)
        r = client.get("/graph")
        g = r.json()
        assert g["source_device"] == "cam-002"
        assert g["propagation_risk"] == pytest.approx(0.72)

    def test_device_registry_updated_after_anomaly(self):
        client.post("/ingest/anomaly", json=VALID_ANOMALY_HIGH)
        # TestClient runs background tasks synchronously
        r = client.get("/devices")
        device_ids = [d["device_id"] for d in r.json()]
        assert "cam-002" in device_ids

    def test_high_risk_anomaly_appears_in_alerts(self):
        client.post("/ingest/anomaly", json=VALID_ANOMALY_HIGH)
        r = client.get("/alerts")
        device_ids = [a["device_id"] for a in r.json()]
        assert "cam-002" in device_ids

    def test_low_risk_anomaly_not_in_alerts(self):
        """Low risk should update device registry but NOT create an alert."""
        client.post("/ingest/anomaly", json=VALID_ANOMALY_LOW)
        r = client.get("/alerts")
        # All alerts for sensor-02 should have risk > threshold
        sensor_alerts = [a for a in r.json() if a["device_id"] == "sensor-02"]
        for a in sensor_alerts:
            assert a["risk_score"] >= ALERT_RISK_THRESHOLD


# ---------------------------------------------------------------------------
# 3. Alert merger logic
# ---------------------------------------------------------------------------

class TestAlertMerger:
    def _make_anomaly(self, risk: float) -> AnomalyResult:
        return AnomalyResult(
            timestamp=_NOW,
            device_id="test-device",
            device_type="camera",
            scores=AnomalyScores(
                isolation_forest=risk,
                autoencoder=risk - 5,
                final_risk=risk,
                confidence="high",
            ),
            reason_codes=["test_code"],
            explanations=["Test explanation"],
        )

    def test_build_alert_event_without_graph(self):
        anomaly = self._make_anomaly(80.0)
        alert = build_alert_event(anomaly)
        assert isinstance(alert, AlertEvent)
        assert alert.device_id == "test-device"
        assert alert.risk_score == 80.0
        assert alert.mitre.tactic == "Unknown"
        assert alert.graph.path == ["test-device"]

    def test_build_alert_event_with_graph(self):
        anomaly = self._make_anomaly(80.0)
        graph = GraphEnrichment(
            timestamp=_NOW,
            source_device="test-device",
            propagation_risk=0.88,
            neighbors=["router-01"],
            next_target_prediction=[
                NextTargetPrediction(device_id="router-01", score=0.9, why="high centrality")
            ],
            attack_paths=[["test-device", "router-01"]],
            mitre=MITRETag(tactic="Lateral Movement", technique="T1021"),
        )
        alert = build_alert_event(anomaly, graph)
        assert alert.mitre.tactic == "Lateral Movement"
        assert alert.graph.path == ["test-device", "router-01"]
        assert alert.graph.next_targets == ["router-01"]

    def test_severity_bands(self):
        assert build_alert_event(self._make_anomaly(90.0)).severity == "critical"
        assert build_alert_event(self._make_anomaly(75.0)).severity == "high"
        assert build_alert_event(self._make_anomaly(55.0)).severity == "medium"
        assert build_alert_event(self._make_anomaly(30.0)).severity == "low"


# ---------------------------------------------------------------------------
# 4. Report endpoints
# ---------------------------------------------------------------------------

class TestReportEndpoints:
    def test_post_report_uses_real_builder(self):
        """build_report() should produce a dynamic report_id (not the hardcoded mock)."""
        payload = MOCK_ALERTS[0].model_dump(mode="json")
        r = client.post("/report", json=payload)
        assert r.status_code == 200
        report = r.json()
        IncidentReport(**report)  # schema validation
        # Real builder generates a dynamic ID starting with "rep_"
        assert report["report_id"].startswith("rep_")
        assert len(report["recommendations"]) > 0

    def test_pdf_endpoint_404_unknown_event(self):
        r = client.get("/report/nonexistent_event_id/pdf")
        assert r.status_code == 404

    def test_pdf_endpoint_200_for_stored_alert(self):
        """Ingest a high-risk anomaly → the generated alert should be PDF-able."""
        client.post("/ingest/anomaly", json=VALID_ANOMALY_HIGH)
        # Get the alert from the store
        alerts_r = client.get("/alerts")
        cam_alerts = [a for a in alerts_r.json() if a["device_id"] == "cam-002"]
        assert cam_alerts, "Expected at least one cam-002 alert in store"
        event_id = cam_alerts[0]["event_id"]

        pdf_r = client.get(f"/report/{event_id}/pdf")
        assert pdf_r.status_code == 200
        assert "application/pdf" in pdf_r.headers["content-type"]
        assert len(pdf_r.content) > 0
