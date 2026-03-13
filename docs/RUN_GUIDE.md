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
curl -X POST http://localhost:8000/report \
  -H "Content-Type: application/json" \
  -d '{"event_id":"evt_4f20","format":"json"}'
```

---

## 7. Integration Day Workflow

Use this order on Day 4:

1. Start backend and frontend.
2. Feed P1 score output into backend.
3. Feed P2 enrichment output into backend.
4. Confirm websocket updates appear in UI.
5. Trigger report generation from UI and API.

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
