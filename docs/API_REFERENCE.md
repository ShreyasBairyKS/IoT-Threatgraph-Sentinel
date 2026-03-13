# API Reference

This document is the contract for IoT ThreatGraph Sentinel APIs and websocket events.

---

## 1. Base URL

| Environment | URL |
|---|---|
| Local | `http://localhost:8000` |
| Docker Compose | `http://localhost:8000` |

---

## 2. Endpoints

## `GET /health`

Liveness check for API process.

### Response

```json
{
  "status": "ok"
}
```

---

## `GET /devices`

Returns current device snapshot with risk metadata.

### Response

```json
[
  {
    "device_id": "cam-001",
    "device_type": "camera",
    "last_seen": "2026-03-12T09:10:00Z",
    "risk_score": 87,
    "confidence": "high",
    "status": "critical"
  }
]
```

---

## `GET /alerts`

Returns latest enriched alert events.

### Response

```json
[
  {
    "event_type": "alert.created",
    "event_id": "evt_4f20",
    "timestamp": "2026-03-12T09:10:07Z",
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
]
```

---

## `GET /graph`

Returns graph nodes, edges, and optional replay frame metadata.

### Response

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

## `POST /ingest/graph`

Ingest a single graph enrichment payload from P2.

### Request

```json
{
  "timestamp": "2026-03-12T09:01:05Z",
  "source_device": "cam-001",
  "propagation_risk": 0.81,
  "neighbors": ["router-02", "nvr-01"],
  "next_target_prediction": [
    {"device_id": "router-02", "score": 0.88, "why": "high betweenness centrality"}
  ],
  "attack_paths": [["cam-001", "router-02", "access-ctrl-01"]],
  "mitre": {"tactic": "Lateral Movement", "technique": "T1021"}
}
```

### Response

```json
{
  "status": "accepted",
  "source_device": "cam-001"
}
```

---

## `POST /ingest/graph/batch`

Ingest multiple graph enrichment payloads in one request.

### Request

```json
[
  {
    "timestamp": "2026-03-12T09:01:05Z",
    "source_device": "cam-001",
    "propagation_risk": 0.81,
    "neighbors": ["router-02"],
    "next_target_prediction": [
      {"device_id": "router-02", "score": 0.88, "why": "high betweenness centrality"}
    ],
    "attack_paths": [["cam-001", "router-02", "access-ctrl-01"]],
    "mitre": {"tactic": "Lateral Movement", "technique": "T1021"}
  }
]
```

### Response

```json
{
  "status": "accepted",
  "count": 1
}
```

---

## `POST /report`

Generates structured incident output from alert evidence.

### Request

```json
{
  "event_type": "alert.created",
  "event_id": "evt_4f20",
  "timestamp": "2026-03-12T09:10:07Z",
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

### Response

```json
{
  "report_id": "rep_001",
  "generated_at": "2026-03-12T09:12:00Z",
  "incident_summary": "Potential lateral movement initiated from cam-001",
  "affected_devices": ["cam-001", "router-02"],
  "evidence": {
    "risk_score": 87,
    "explanations": [
      "Outbound traffic is 6.8x above rolling baseline",
      "Likely propagation path detected"
    ],
    "mitre": [
      {
        "tactic": "Lateral Movement",
        "technique": "T1021"
      }
    ]
  },
  "recommendations": [
    "Isolate cam-001 into quarantine VLAN",
    "Block outbound connections to unseen external endpoints"
  ]
}
```

### PDF Download

- `GET /report/{event_id}/pdf`
- `200 OK`
- `Content-Type: application/pdf`
- Body is binary PDF stream.

---

## 3. WebSocket Contract

## `WS /ws/alerts`

Pushes real-time alert events to frontend.

### Event: `alert.created`

```json
{
  "event_type": "alert.created",
  "event_id": "evt_4f20",
  "timestamp": "2026-03-12T09:10:07Z",
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

## 4. Validation Rules

- `risk_score`: integer in `0-100`.
- `confidence`: one of `low`, `medium`, `high`.
- `severity`: one of `low`, `medium`, `high`, `critical`.
- `device_id` and `event_id`: non-empty strings.
- `mitre.technique`: ATT&CK technique id format (for example `T1021`).

---

## 5. Error Responses

### `422 Unprocessable Entity`

Returned when payload validation fails.

### `500 Internal Server Error`

```json
{
  "error": "internal_server_error"
}
```

### `503 Service Unavailable`

```json
{
  "error": "stream_unavailable"
}
```

Used when live event source is temporarily down.
