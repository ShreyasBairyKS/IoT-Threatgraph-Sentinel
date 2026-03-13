"""
tests/test_contracts.py - Day 1 contract validation tests for P3.

Validates that:
  1. All mock payloads pass Pydantic model validation (no runtime surprises).
  2. All REST endpoints return HTTP 200 and contract-compliant JSON.
  3. Malformed payloads are correctly rejected.

Run:
    pytest tests/ -v
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.contracts import (
    AlertEvent,
    DeviceSummary,
    GraphEnrichment,
    IncidentReport,
)
from backend.mocks.mock_store import MOCK_ALERTS, MOCK_DEVICES, MOCK_GRAPH, MOCK_REPORT

client = TestClient(app)


# ---------------------------------------------------------------------------
# Mock store integrity
# ---------------------------------------------------------------------------

class TestMockStoreIntegrity:
    def test_mock_devices_are_valid(self):
        for d in MOCK_DEVICES:
            assert isinstance(d, DeviceSummary)

    def test_mock_alerts_are_valid(self):
        for a in MOCK_ALERTS:
            assert isinstance(a, AlertEvent)

    def test_mock_graph_is_valid(self):
        assert isinstance(MOCK_GRAPH, GraphEnrichment)
        assert 0.0 <= MOCK_GRAPH.propagation_risk <= 1.0

    def test_mock_report_is_valid(self):
        assert isinstance(MOCK_REPORT, IncidentReport)
        assert len(MOCK_REPORT.recommendations) > 0


# ---------------------------------------------------------------------------
# REST endpoint smoke tests
# ---------------------------------------------------------------------------

class TestEndpoints:
    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_get_devices(self):
        r = client.get("/devices")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) > 0
        # Validate first item against model
        DeviceSummary(**data[0])

    def test_get_alerts(self):
        r = client.get("/alerts")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        AlertEvent(**data[0])

    def test_get_graph(self):
        r = client.get("/graph")
        assert r.status_code == 200
        GraphEnrichment(**r.json())

    def test_post_report_with_valid_payload(self):
        alert_payload = MOCK_ALERTS[0].model_dump(mode="json")
        r = client.post("/report", json=alert_payload)
        assert r.status_code == 200
        IncidentReport(**r.json())

    def test_post_report_rejects_malformed_payload(self):
        r = client.post("/report", json={"bad": "payload"})
        assert r.status_code == 422  # Pydantic validation error


# ---------------------------------------------------------------------------
# Contract field presence
# ---------------------------------------------------------------------------

class TestContractFieldPresence:
    """Ensure required fields are present in responses (catches silent drops)."""

    def test_alert_has_required_fields(self):
        r = client.get("/alerts")
        alert = r.json()[0]
        for field in ["event_type", "event_id", "timestamp", "severity",
                      "device_id", "risk_score", "confidence", "reasons", "mitre", "graph"]:
            assert field in alert, f"Missing field: {field}"

    def test_graph_has_required_fields(self):
        r = client.get("/graph")
        g = r.json()
        for field in ["source_device", "propagation_risk", "attack_paths",
                      "next_target_prediction", "mitre"]:
            assert field in g, f"Missing field: {field}"

    def test_alert_event_type_is_frozen(self):
        r = client.get("/alerts")
        for alert in r.json():
            assert alert["event_type"] == "alert.created"
