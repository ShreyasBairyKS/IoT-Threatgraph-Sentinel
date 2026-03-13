# Data Model

This document defines core payload schemas and model fields used across ML, graph, backend, and frontend.

---

## 1. Canonical IDs and Time Fields

| Field | Type | Notes |
|---|---|---|
| `device_id` | `string` | Stable unique id per device |
| `event_id` | `string` | Unique id per alert event |
| `report_id` | `string` | Unique id per report |
| `timestamp` | `string` | ISO-8601 UTC |
| `window_start` | `string` | ISO-8601 UTC |
| `window_end` | `string` | ISO-8601 UTC |

---

## 2. Feature Window Schema (P1 output)

```json
{
  "window_start": "2026-03-12T09:00:00Z",
  "window_end": "2026-03-12T09:01:00Z",
  "device_id": "cam-001",
  "features": {
    "flow_duration_mean": 1.24,
    "packet_rate": 52.1,
    "byte_volume": 81234,
    "port_entropy": 2.18,
    "unique_dest_ips": 9,
    "tcp_ratio": 0.64,
    "udp_ratio": 0.35,
    "iat_mean": 0.092,
    "iat_std": 0.031
  }
}
```

### Notes

- Feature keys are snake_case.
- Numeric features use `float` unless naturally integral counts.
- Missing features must be imputed before model scoring.

---

## 3. Anomaly Result Schema (P1 -> P2/P3)

```json
{
  "timestamp": "2026-03-12T09:01:00Z",
  "device_id": "cam-001",
  "device_type": "camera",
  "scores": {
    "isolation_forest": 78.4,
    "autoencoder": 64.2,
    "final_risk": 73.1,
    "confidence": "high"
  },
  "reason_codes": ["outbound_volume_spike", "dest_ip_diversity_jump"],
  "explanations": [
    "Outbound traffic is 6.8x above rolling baseline",
    "Unique destination IP count increased from 2 to 9"
  ]
}
```

---

## 4. Graph Enrichment Schema (P2 -> P3/P4)

```json
{
  "timestamp": "2026-03-12T09:01:05Z",
  "source_device": "cam-001",
  "propagation_risk": 0.81,
  "neighbors": ["router-02", "nvr-01", "sensor-07"],
  "next_target_prediction": [
    {"device_id": "router-02", "score": 0.88, "why": "high betweenness centrality"}
  ],
  "attack_paths": [["cam-001", "router-02", "access-ctrl-01"]],
  "mitre": {
    "tactic": "Lateral Movement",
    "technique": "T1021"
  }
}
```

---

## 5. Alert Event Schema (P3 websocket output)

```json
{
  "event_type": "alert.created",
  "event_id": "evt_4f20",
  "timestamp": "2026-03-12T09:01:07Z",
  "severity": "high",
  "device_id": "cam-001",
  "device_type": "camera",
  "risk_score": 87,
  "confidence": "high",
  "reasons": [
    "Outbound traffic is 6.8x above rolling baseline",
    "Likely propagation path detected"
  ],
  "mitre": {
    "tactic": "Lateral Movement",
    "technique": "T1021"
  },
  "graph": {
    "path": ["cam-001", "router-02", "access-ctrl-01"],
    "next_targets": ["router-02", "nvr-01"]
  }
}
```

---

## 6. Incident Report Schema (P3 output)

```json
{
  "report_id": "rep_001",
  "generated_at": "2026-03-12T09:02:00Z",
  "incident_summary": "Potential lateral movement initiated from cam-001",
  "affected_devices": ["cam-001", "router-02", "access-ctrl-01"],
  "evidence": {
    "risk_score": 87,
    "explanations": ["Outbound traffic spike", "Unusual destination fan-out"],
    "mitre": [{"tactic": "Lateral Movement", "technique": "T1021"}]
  },
  "recommendations": [
    "Isolate cam-001 into quarantine VLAN",
    "Block outbound connections to unseen external endpoints"
  ]
}
```

---

## 7. Enumerations

### `confidence`

- `low`
- `medium`
- `high`

### `severity`

- `low`
- `medium`
- `high`
- `critical`

---

## 8. Storage Mapping

| Data | Primary Store |
|---|---|
| Raw packet/flow data | Files or object storage |
| Feature windows | Parquet/CSV or stream topic |
| Model artifacts | `artifacts/models/` |
| Graph entities/edges | NetworkX in-memory and/or persisted graph store |
| Alert history | Backend datastore (implementation-specific) |
| Generated PDFs | Local disk or object storage |

---

## 9. Contract Governance

- Contract files are frozen on Day 1.
- Any breaking schema change requires approval from P1, P2, P3, and P4.
- New optional fields must be backward-compatible.
