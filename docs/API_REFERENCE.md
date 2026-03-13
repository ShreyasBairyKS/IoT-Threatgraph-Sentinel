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
{
  "items": [
    {
      "device_id": "cam-001",
      "device_type": "camera",
      "risk_score": 87,
      "confidence": "high",
      "last_seen": "2026-03-12T09:10:00Z"
    }
  ]
}
```

---

## `GET /alerts`

Returns latest enriched alert events.

### Response

```json
{
  "items": [
    {
      "event_id": "evt_4f20",
      "timestamp": "2026-03-12T09:10:07Z",
      "severity": "high",
      "device_id": "cam-001",
      "risk_score": 87,
      "mitre": {
        "tactic": "Lateral Movement",
        "technique": "T1021"
      },
      "reasons": [
        "Outbound traffic is 6.8x above rolling baseline",
        "Likely propagation path detected"
      ]
    }
  ]
}
```

---

## `GET /graph`

Returns graph nodes, edges, and optional replay frame metadata.

### Response

```json
{
  "nodes": [
    {"id": "cam-001", "label": "Camera 001", "risk_score": 87}
  ],
  "edges": [
    {"id": "e1", "source": "cam-001", "target": "router-02", "weight": 0.72}
  ],
  "replay": {
    "frame_count": 120,
    "start": "2026-03-12T09:00:00Z",
    "end": "2026-03-12T09:20:00Z"
  }
}
```

---

## `POST /report`

Generates structured incident output from alert evidence.

### Request

```json
{
  "event_id": "evt_4f20",
  "format": "pdf"
}
```

### Response (JSON mode)

```json
{
  "report_id": "rep_001",
  "generated_at": "2026-03-12T09:12:00Z",
  "incident_summary": "Potential lateral movement initiated from cam-001",
  "affected_devices": ["cam-001", "router-02"],
  "recommendations": [
    "Isolate cam-001 into quarantine VLAN",
    "Block outbound connections to unseen external endpoints"
  ]
}
```

### Response (PDF mode)

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
