# Architecture

This document defines the production architecture for IoT ThreatGraph Sentinel.

---

## 1. System Overview

IoT ThreatGraph Sentinel is a near-real-time detection and intelligence platform that:

- extracts network behavior features per device per time window,
- scores anomalies with ML,
- computes graph propagation risk,
- maps activity to MITRE ATT&CK for ICS,
- streams enriched alerts to a live dashboard,
- generates incident reports in JSON and PDF.

### High-Level Flow

```text
Dataset Replay / Live Stream
  -> Feature Extraction (P1)
  -> ML Scoring + Explainability (P1)
  -> Graph Propagation + MITRE Enrichment (P2)
  -> FastAPI + WebSocket Event Bus (P3)
  -> React Dashboard + Replay UI (P4)
```

---

## 2. Runtime Components

| Component | Owner | Responsibility |
|---|---|---|
| `ml-worker` | P1 | Feature windows, Isolation Forest, optional autoencoder, SHAP explanations |
| `graph-worker` | P2 | Graph updates, weighted propagation risk, attack paths, next-target prediction, MITRE mapping |
| `api-server` | P3 | REST APIs, websocket stream, contract validation, report generation |
| `web-client` | P4 | Real-time dashboard, Cytoscape graph, replay timeline, drill-down panels |

---

## 3. Data Boundaries

The architecture is contract-driven and uses frozen payload schemas (see `docs/DATA_MODEL.md`).

### Required one-way dependency flow

- Frontend consumes backend payloads only.
- Backend consumes ML and graph outputs only.
- Graph service consumes anomaly outputs from ML.
- ML is independent of graph/backend/frontend internals.

No reverse imports across domains are allowed.

---

## 4. Detection and Intelligence Pipeline

## Stage A: Feature Engineering

Input: packet/flow data grouped by device and window.
Output: per-device feature vectors (traffic rate, volume, entropy, protocol ratios, inter-arrival stats).

## Stage B: ML Scoring

- Isolation Forest produces anomaly score.
- Optional autoencoder captures subtle drift.
- Final risk score is weighted and normalized.
- Explainability strings are generated for high-risk windows.

## Stage C: Graph Intelligence

- Devices are nodes; communication flows are weighted edges.
- Propagation risk is computed using weighted centrality (PageRank-like approach).
- Attack path tracing predicts likely spread.
- MITRE ATT&CK technique/tactic labels are attached.

## Stage D: Alert and Report Orchestration

- Backend validates incoming intelligence payloads.
- Alert events are emitted over websocket.
- Incident reports are generated on demand from latest evidence.

---

## 5. API and Event Layer

### REST (FastAPI)

- `GET /devices`
- `GET /alerts`
- `GET /graph`
- `POST /report`
- `GET /health`

### WebSocket

- `WS /ws/alerts`
- Event type: `alert.created`

Contract details are specified in `docs/API_REFERENCE.md`.

---

## 6. Frontend Rendering Model

The dashboard has three synchronized regions:

- left panel: device list and risk ranking,
- center panel: network graph and replay timeline,
- right panel: alert stream and evidence details.

Graph state updates are event-driven via websocket, with polling fallback in degraded mode.

---

## 7. Deployment Topology

Recommended deployment for hackathon phase:

- Dockerized services,
- backend and frontend on Render or Railway,
- optional managed Redis for buffering/replay metadata.

For local development, use single-machine Docker Compose.

---

## 8. Non-Functional Targets

- End-to-end alert latency target: < 1.5s during replay.
- Websocket update delivery target: < 1s.
- Incident PDF generation target: < 5s.
- Replay timeline should remain smooth at medium graph size.

---

## 9. Failure Modes and Fallbacks

| Failure | Fallback |
|---|---|
| Autoencoder unstable | Use Isolation Forest only |
| WebSocket unreliable | Poll `GET /alerts` every 3s |
| MITRE mapping gaps | Use curated top tactic-technique mapping |
| Heavy replay lag | Precompute frame snapshots |

---

## 10. Source of Truth

- Team execution plan: `docs/TEAM_EXECUTION_GUIDE.md`
- Role handoff requirements: `docs/ROLE_HANDOFF_CHECKLIST.md`
- API contracts: `docs/API_REFERENCE.md`
- Payload schemas and model fields: `docs/DATA_MODEL.md`
- Build and run instructions: `docs/RUN_GUIDE.md`
