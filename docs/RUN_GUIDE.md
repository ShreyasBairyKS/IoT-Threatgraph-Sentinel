# Run Guide

Run instructions for IoT ThreatGraph Sentinel in local and team-parallel modes.

---

## 1. Prerequisites

- Python 3.11+
- Node.js 20+
- Docker 24+
- Docker Compose v2+

Optional:

- Makefile (if added later)

---

## 2. Recommended Repository Layout

```text
ml/
graph/
backend/
frontend/
artifacts/
docs/
```

---

## 3. Environment Setup

Create local env files:

- `backend/.env`
- `frontend/.env`

Suggested backend variables:

```dotenv
APP_ENV=development
API_PORT=8000
WS_PATH=/ws/alerts
REPORT_OUTPUT_DIR=./artifacts/reports
```

Suggested frontend variables:

```dotenv
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws/alerts
```

---

## 4. Role-Wise Local Run Commands

## P1 - ML pipeline only

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r ml/requirements.txt
python ml/train.py
python ml/replay_score.py --input data/sample_flows.csv --output artifacts/ml_scores.json
```

## P2 - Graph intelligence only

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r graph/requirements.txt
python graph/build_graph.py --input data/sample_flows.csv
python graph/propagation.py --scores artifacts/ml_scores.json --output artifacts/graph_enrichment.json
```

## Integrated P1 -> P2 (new model + next graph phase)

```bash
python ml/run_phase_pipeline.py --input data/sample_flows.csv --datapoints 5000
```

Outputs (default):

- `artifacts/sample_flows_5000.csv`
- `artifacts/features_5000.json`
- `artifacts/ml_scores_5000.json`
- `artifacts/graph_5000.json`
- `artifacts/graph_enrichment_5000.json`

## P3 - Backend API and websocket

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

## P4 - Frontend dashboard

```bash
cd frontend
npm install
npm run dev
```

Frontend default URL: `http://localhost:5173`

---

## 5. Full Local Stack (Docker Compose)

```bash
docker compose up --build
```

Expected local endpoints:

- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- Frontend: `http://localhost:5173`

---

## 6. Basic Smoke Checks

Health check:

```bash
curl http://localhost:8000/health
```

Fetch devices:

```bash
curl http://localhost:8000/devices
```

Open websocket (example using `wscat`):

```bash
wscat -c ws://localhost:8000/ws/alerts
```

Generate report:

```bash
# /report expects a full AlertEvent payload.
# Quick smoke path: fetch one alert, then post it to /report.
curl http://localhost:8000/alerts

curl -X POST http://localhost:8000/report \
  -H "Content-Type: application/json" \
  -d '{
    "event_type":"alert.created",
    "event_id":"evt_4f20",
    "timestamp":"2026-03-13T06:00:00Z",
    "severity":"high",
    "device_id":"cam-001",
    "device_type":"camera",
    "risk_score":87,
    "confidence":"high",
    "reasons":["Outbound traffic is 6.8x above rolling baseline"],
    "mitre":{"tactic":"Lateral Movement","technique":"T1021"},
    "graph":{"path":["cam-001","router-02"],"next_targets":["router-02"]}
  }'
```

Download report PDF for a stored alert:

```bash
curl -L http://localhost:8000/report/evt_4f20/pdf --output report_evt_4f20.pdf
```

---

## 7. Integration Day Workflow

Use this order on Day 4:

1. Start backend and frontend.
2. Run graph build first so `artifacts/graph.json` is populated.
3. Run P1 scoring and produce `artifacts/ml_scores.json`.
4. Run P2 propagation and produce `artifacts/graph_enrichment.json`.
5. Feed P2 enrichment output into backend (`POST /ingest/graph` per object or `POST /ingest/graph/batch` for arrays).
6. Feed P1 score output into backend (`POST /ingest/anomaly`).
7. Confirm websocket updates appear in UI.
8. Trigger report generation from UI and API.

Note: if propagation runs against an empty graph, enrichments will contain empty neighbors/paths and near-zero propagation risk.

---

## 8. Troubleshooting

### No websocket updates

- Verify backend websocket path matches frontend env variable.
- Ensure event payload includes `event_type`.

### Frontend graph not rendering

- Check node ids are unique and non-empty.
- Confirm edge `source` and `target` ids exist in nodes.

### Report generation fails

- Confirm `event_id` exists in alert history.
- Verify report output directory write permissions.

---

## 9. Demo Mode

For stable live demo:

- use prerecorded replay input,
- lock random seeds for deterministic scoring,
- disable noisy debug logs,
- keep fallback demo video ready.
