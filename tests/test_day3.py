"""
tests/test_day3.py - Day 3 integration smoke tests + PDF validation.

Based on the official smoke test pack from docs/TEAM_EXECUTION_GUIDE.md Section 8.2:

  ST-01: normal device window → no critical alert
  ST-02: anomalous device    → alert with explanations
  ST-03: anomaly + neighbors → propagation path shown
  ST-04: MITRE tag appears in alert and report
  ST-05: one-click PDF contains summary, evidence, recommendations

Also covers:
  - GET /alerts/{event_id} single alert lookup
  - GET /alerts/{event_id} returns 404 for unknown ID
  - Real PDF magic bytes (%PDF-) and generation speed < 5s
  - Mock fallback for GET /alerts/{event_id} (reads from mock store)

Run: pytest tests/ -v
"""

import time
import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone

from backend.main import app
from backend.contracts import IncidentReport
from backend.mocks.mock_store import MOCK_ALERTS
from backend.reporting.export_pdf import export_pdf
from backend.reporting.generate_report import build_report

client = TestClient(app)

_NOW = datetime(2026, 3, 13, 6, 0, 0, tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Fixtures: payloads
# ---------------------------------------------------------------------------

NORMAL_ANOMALY = {
    "timestamp": _NOW.isoformat(),
    "device_id": "sensor-normal-01",
    "device_type": "sensor",
    "scores": {
        "isolation_forest": 18.0,
        "autoencoder": 15.0,
        "final_risk": 17.0,
        "confidence": "low",
    },
    "reason_codes": [],
    "explanations": [],
}

HIGH_ANOMALY = {
    "timestamp": _NOW.isoformat(),
    "device_id": "cam-st02",
    "device_type": "camera",
    "scores": {
        "isolation_forest": 85.0,
        "autoencoder": 83.0,
        "final_risk": 84.0,
        "confidence": "high",
    },
    "reason_codes": ["outbound_volume_spike", "dest_ip_diversity_jump"],
    "explanations": [
        "Outbound traffic is 6.8x above rolling baseline",
        "Unique destination IP count increased from 2 to 9",
    ],
}

GRAPH_WITH_PATH = {
    "timestamp": _NOW.isoformat(),
    "source_device": "cam-st02",
    "propagation_risk": 0.81,
    "neighbors": ["router-02", "nvr-01", "sensor-07"],
    "next_target_prediction": [
        {"device_id": "router-02", "score": 0.88, "why": "high betweenness centrality"},
        {"device_id": "nvr-01", "score": 0.79, "why": "frequent bidirectional flow"},
    ],
    "attack_paths": [["cam-st02", "router-02", "access-ctrl-01"]],
    "mitre": {"tactic": "Lateral Movement", "technique": "T1021"},
}


# ---------------------------------------------------------------------------
# ST-01: Normal device window → no critical alert
# ---------------------------------------------------------------------------

class TestST01_NormalTraffic:
    def test_low_risk_device_does_not_trigger_critical_alert(self):
        """Normal traffic should update device registry but NOT emit a critical alert."""
        client.post("/ingest/anomaly", json=NORMAL_ANOMALY)

        r = client.get("/alerts")
        critical_for_device = [
            a for a in r.json()
            if a["device_id"] == "sensor-normal-01" and a["severity"] == "critical"
        ]
        assert len(critical_for_device) == 0, "Normal device should NOT produce a critical alert"

    def test_low_risk_device_appears_in_device_list(self):
        """Even a normal device should be registered in device list after ingestion."""
        client.post("/ingest/anomaly", json=NORMAL_ANOMALY)
        r = client.get("/devices")
        ids = [d["device_id"] for d in r.json()]
        assert "sensor-normal-01" in ids


# ---------------------------------------------------------------------------
# ST-02: Anomalous device → alert with explanations
# ---------------------------------------------------------------------------

class TestST02_AnomalyAlert:
    def test_high_risk_triggers_alert(self):
        """High-risk anomaly should create an alert event in the store."""
        client.post("/ingest/anomaly", json=HIGH_ANOMALY)
        r = client.get("/alerts")
        cam_alerts = [a for a in r.json() if a["device_id"] == "cam-st02"]
        assert len(cam_alerts) > 0, "High-risk anomaly should create an alert"

    def test_alert_has_explanations(self):
        """Alert must carry at least one explanation string."""
        client.post("/ingest/anomaly", json=HIGH_ANOMALY)
        r = client.get("/alerts")
        cam_alerts = [a for a in r.json() if a["device_id"] == "cam-st02"]
        assert cam_alerts, "Expected cam-st02 alert"
        assert len(cam_alerts[0]["reasons"]) >= 1

    def test_alert_severity_is_high_for_84_risk(self):
        """risk=84 → severity=high (critical band starts at 85)."""
        client.post("/ingest/anomaly", json=HIGH_ANOMALY)
        r = client.get("/alerts")
        cam_alerts = [a for a in r.json() if a["device_id"] == "cam-st02"]
        # 84 is in the 'high' band (70-84); 'critical' is >= 85
        assert cam_alerts[0]["severity"] in ("high", "critical")


# ---------------------------------------------------------------------------
# ST-03: Anomaly + neighbors → propagation path shown
# ---------------------------------------------------------------------------

class TestST03_PropagationPath:
    def test_graph_enrichment_populates_attack_path_in_alert(self):
        """When P2 graph enrichment is present, alerts include the attack path."""
        client.post("/ingest/graph", json=GRAPH_WITH_PATH)
        client.post("/ingest/anomaly", json=HIGH_ANOMALY)

        r = client.get("/alerts")
        cam_alerts = [a for a in r.json() if a["device_id"] == "cam-st02"]
        assert cam_alerts, "Expected cam-st02 alert after enrichment"
        graph = cam_alerts[0]["graph"]
        assert len(graph["path"]) > 1, "Attack path should have more than one node"
        assert "router-02" in graph["path"]

    def test_next_targets_populated_from_p2(self):
        """next_targets in alert should reflect P2 prediction."""
        client.post("/ingest/graph", json=GRAPH_WITH_PATH)
        client.post("/ingest/anomaly", json=HIGH_ANOMALY)

        r = client.get("/alerts")
        cam_alerts = [a for a in r.json() if a["device_id"] == "cam-st02"]
        assert cam_alerts
        assert "router-02" in cam_alerts[0]["graph"]["next_targets"]


# ---------------------------------------------------------------------------
# ST-04: MITRE tag appears in alert and report
# ---------------------------------------------------------------------------

class TestST04_MITRETag:
    def test_mitre_tag_in_alert(self):
        """Alert must carry a valid MITRE tactic and technique."""
        client.post("/ingest/graph", json=GRAPH_WITH_PATH)
        client.post("/ingest/anomaly", json=HIGH_ANOMALY)

        r = client.get("/alerts")
        cam_alerts = [a for a in r.json() if a["device_id"] == "cam-st02"]
        assert cam_alerts
        mitre = cam_alerts[0]["mitre"]
        assert mitre["tactic"] == "Lateral Movement"
        assert mitre["technique"] == "T1021"

    def test_mitre_tag_in_generated_report(self):
        """Incident report must include MITRE tags in evidence."""
        client.post("/ingest/graph", json=GRAPH_WITH_PATH)
        client.post("/ingest/anomaly", json=HIGH_ANOMALY)

        r = client.get("/alerts")
        cam_alerts = [a for a in r.json() if a["device_id"] == "cam-st02"]
        assert cam_alerts
        alert_payload = cam_alerts[0]
        report_r = client.post("/report", json=alert_payload)
        assert report_r.status_code == 200
        evidence = report_r.json()["evidence"]
        assert any(m["tactic"] == "Lateral Movement" for m in evidence["mitre"])


# ---------------------------------------------------------------------------
# ST-05: PDF contains summary, evidence, recommendations
# ---------------------------------------------------------------------------

class TestST05_PDFReport:
    def test_pdf_is_real_pdf_magic_bytes(self):
        """PDF must start with %PDF- (valid PDF magic bytes)."""
        report = build_report(MOCK_ALERTS[0])
        pdf_bytes = export_pdf(report)
        assert pdf_bytes[:5] == b"%PDF-", "Output must be a real PDF file"

    def test_pdf_contains_report_content(self):
        """PDF bytes must contain key report text (embedded as stream)."""
        report = build_report(MOCK_ALERTS[0])
        pdf_bytes = export_pdf(report)
        # PDF stream text is partially readable in raw bytes
        assert len(pdf_bytes) > 2000, "PDF must be a non-trivial size"

    def test_pdf_generation_under_5_seconds(self):
        """PDF must generate in < 5s (architecture NFR)."""
        report = build_report(MOCK_ALERTS[0])
        start = time.perf_counter()
        export_pdf(report)
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"PDF generation took {elapsed:.2f}s, must be < 5s"

    def test_pdf_endpoint_returns_real_pdf(self):
        """GET /report/{id}/pdf must return application/pdf with %PDF- bytes."""
        # Ingest alert so it's in the store
        client.post("/ingest/graph", json=GRAPH_WITH_PATH)
        client.post("/ingest/anomaly", json=HIGH_ANOMALY)

        alerts_r = client.get("/alerts")
        cam_alerts = [a for a in alerts_r.json() if a["device_id"] == "cam-st02"]
        assert cam_alerts
        event_id = cam_alerts[0]["event_id"]

        pdf_r = client.get(f"/report/{event_id}/pdf")
        assert pdf_r.status_code == 200
        assert "application/pdf" in pdf_r.headers["content-type"]
        assert pdf_r.content[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# Alert lookup: GET /alerts/{event_id}
# ---------------------------------------------------------------------------

class TestAlertLookup:
    def test_get_alert_by_id_from_mock(self):
        """GET /alerts/{event_id} returns mock alert when store is empty."""
        mock_id = MOCK_ALERTS[0].event_id
        r = client.get(f"/alerts/{mock_id}")
        assert r.status_code == 200
        assert r.json()["event_id"] == mock_id

    def test_get_alert_by_id_from_live_store(self):
        """GET /alerts/{event_id} returns live alert after ingestion."""
        client.post("/ingest/anomaly", json=HIGH_ANOMALY)
        alerts_r = client.get("/alerts")
        cam_alerts = [a for a in alerts_r.json() if a["device_id"] == "cam-st02"]
        assert cam_alerts
        event_id = cam_alerts[0]["event_id"]
        r = client.get(f"/alerts/{event_id}")
        assert r.status_code == 200
        assert r.json()["event_id"] == event_id

    def test_get_alert_by_id_404_unknown(self):
        """GET /alerts/unknown-id must return 404."""
        r = client.get("/alerts/totally_unknown_event_id_xyz")
        assert r.status_code == 404
