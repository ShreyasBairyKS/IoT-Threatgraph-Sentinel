# Role and File Breakdown (P1-P4)

This guide explains what each person (P1, P2, P3, P4) built, starting from basic concepts and moving to advanced integration behavior. It also maps each important file to its function.

## 1. Basic System View

1. P1 reads traffic data and converts it into anomaly intelligence.
2. P2 reads communication patterns and adds graph propagation intelligence.
3. P3 receives P1 and P2 outputs, validates contracts, stores runtime state, and exposes APIs/WebSocket.
4. P4 consumes those APIs/events and renders a live dashboard for operations and demo.

Pipeline flow:

`data -> P1 (ML) -> P2 (graph intel) -> P3 (backend APIs/WS/report) -> P4 (frontend UI)`

## 2. P1 (Data and ML)

### P1 from basic to advanced

1. Basic: convert flow rows into a standard feature vector per device/window.
2. Intermediate: train anomaly and classification models.
3. Advanced: infer risk using model fusion and generate explainability text.

### P1 file functions

- `ml/features.py`: Core feature engineering engine.
- `ml/features.py`: Loads CSV, groups traffic into time windows, computes feature keys like `packet_rate`, `byte_volume`, `port_entropy`, `iat_mean`, `iat_std`.
- `ml/features.py`: Produces contract-compliant feature-window payloads.

- `ml/train.py`: Model training pipeline.
- `ml/train.py`: Trains `IsolationForest` for anomalies.
- `ml/train.py`: Trains `RandomForestClassifier` for device type prediction.
- `ml/train.py`: Trains optional autoencoder-style drift model (`MLPRegressor`).
- `ml/train.py`: Saves artifacts in `artifacts/models/` (`scaler.pkl`, `isolation_forest.pkl`, `device_classifier.pkl`, `device_classes.pkl`, `autoencoder.pkl`, `autoencoder_meta.pkl`).

- `ml/infer.py`: Runtime inference pipeline.
- `ml/infer.py`: Loads trained artifacts.
- `ml/infer.py`: Calculates anomaly score from Isolation Forest.
- `ml/infer.py`: Calculates optional autoencoder drift score.
- `ml/infer.py`: Fuses scores into `final_risk` using weighted blending.
- `ml/infer.py`: Produces explanation text using SHAP path (if available) with deterministic fallback.
- `ml/infer.py`: Outputs contract payload matching backend expectations.

- `ml/score_window.py`: Day-1 baseline scoring module.
- `ml/score_window.py`: Defines `ScoreResult` contract serializer and simple heuristic scorer.
- `ml/score_window.py`: Still useful as a fallback/simple baseline.

- `ml/replay_score.py`: Replay utility.
- `ml/replay_score.py`: Reads a CSV, aggregates per device, scores with baseline function, writes anomaly JSON.

- `ml/requirements.txt`: P1 dependency set (`numpy`, `scikit-learn`, optional SHAP note).

### P1 tests and validation files

- `ml/tests/test_features.py`: Validates feature extraction, windowing, helpers, CLI output.
- `ml/tests/test_infer.py`: Validates model inference outputs, fusion, confidence logic, explainability paths, latency guard.
- `ml/tests/test_replay_score.py`: Validates replay scoring output structure and bounds.
- `ml/tests/test_score_window.py`: Validates baseline scorer contract and behavior.

## 3. P2 (Graph and Threat Intelligence)

### P2 from basic to advanced

1. Basic: build network graph from traffic communication pairs.
2. Intermediate: compute propagation risk and likely next targets.
3. Advanced: trace attack paths and map behavior into MITRE ATT&CK tags.

### P2 file functions

- `graph/build_graph.py`: Graph builder.
- `graph/build_graph.py`: Reads flow CSV and creates directed graph nodes/edges with edge weights.
- `graph/build_graph.py`: Serializes graph to JSON for later analysis.

- `graph/propagation.py`: Graph intelligence engine.
- `graph/propagation.py`: Runs personalized PageRank-style logic for propagation risk.
- `graph/propagation.py`: Produces `next_target_prediction`.
- `graph/propagation.py`: Traces multi-hop attack paths.
- `graph/propagation.py`: Maps reason codes to MITRE tactics/techniques.
- `graph/propagation.py`: Emits contract-compliant graph enrichment payload.

- `graph/models.py`: P2-side Pydantic model definitions for graph and anomaly payloads.

- `graph/requirements.txt`: P2 dependency set.

### P2 tests

- `graph/tests/test_propagation.py`: Validates propagation risk, path tracing, and MITRE mapping logic.

## 4. P3 (Backend Platform)

### P3 from basic to advanced

1. Basic: expose REST endpoints and health checks.
2. Intermediate: validate all incoming/outgoing contracts and keep runtime state stores.
3. Advanced: real-time ingestion flow, websocket broadcast, report generation, and PDF export.

### P3 core backend files

- `backend/main.py`: FastAPI app entry point.
- `backend/main.py`: Registers routers, health endpoint, websocket endpoint, startup lifecycle.

- `backend/contracts.py`: Single source of truth for frozen API/WS schemas.
- `backend/contracts.py`: Defines FeatureWindow, AnomalyResult, GraphEnrichment, AlertEvent, IncidentReport, DeviceSummary models.

- `backend/config.py`: Environment-driven settings (timings, store limits, app metadata).

- `backend/store.py`: In-memory runtime state layer.
- `backend/store.py`: Keeps alert store, device registry, latest graph snapshot.
- `backend/store.py`: Merges anomaly + graph into final alert payload with severity mapping.

### P3 router files

- `backend/routers/devices.py`: `GET /devices` from live registry with mock fallback.
- `backend/routers/alerts.py`: `GET /alerts`, `GET /alerts/{event_id}` from live store with fallback.
- `backend/routers/graph.py`: `GET /graph` from latest enrichment snapshot with fallback.
- `backend/routers/report.py`: `POST /report` (full `AlertEvent` input), `GET /report/{event_id}/pdf`.
- `backend/routers/ingest.py`: `POST /ingest/anomaly`, `POST /ingest/graph`; triggers store updates + websocket broadcasts.

### P3 reporting and websocket files

- `backend/reporting/generate_report.py`: Builds incident-report JSON from alert evidence and recommendations.
- `backend/reporting/export_pdf.py`: Exports styled PDF report (ReportLab).
- `backend/ws/broadcaster.py`: WebSocket connection manager and mock broadcast loop.

### P3 mock and fallback files

- `backend/mocks/mock_store.py`: Contract-compliant mock devices, alerts, graph, and report used for bootstrap/fallback behavior.

## 5. P4 (Frontend Dashboard)

### P4 from basic to advanced

1. Basic: render the three-panel dashboard shell.
2. Intermediate: visualize devices, alerts, and graph topology.
3. Advanced: drill-down incident context, replay timeline, and event-driven updates.

### P4 frontend files

- `frontend/src/main.tsx`: React app bootstrap.
- `frontend/src/App.tsx`: Main orchestration layer wiring DeviceList, ThreatGraph, AlertFeed, IncidentPanel, ReplayTimeline.
- `frontend/src/App.tsx`: Handles selected device, latest alert focus, replay frame navigation, and mock websocket event updates.

- `frontend/src/components/DeviceList.tsx`: Risk-ranked device panel with confidence/status visualization.
- `frontend/src/components/AlertFeed.tsx`: Alert stream panel with severity badges, MITRE chips, and click-to-drill behavior.
- `frontend/src/components/ThreatGraph.tsx`: Cytoscape graph renderer with suspicious path highlighting and propagation legend.
- `frontend/src/components/IncidentPanel.tsx`: Right-side drill-down with trend chart, explanations, path view, and recommendations.
- `frontend/src/components/ReplayTimeline.tsx`: Playback controls and slider for deterministic replay progression.
- `frontend/src/components/replayUtils.ts`: Helper to convert alert stream to replay frames.

- `frontend/src/types/contracts.ts`: P4 TypeScript interfaces mirroring frozen backend contracts.
- `frontend/src/mocks/*`: Mock API/WS data for offline UI development.
- `frontend/package.json`: Frontend scripts (`dev`, `build`, `lint`, `preview`) and dependencies.

## 6. Cross-Team Integration Files

- `tests/test_contracts.py`: Contract and endpoint validations.
- `tests/test_day2.py`: Ingestion/store/report integration checks.
- `tests/test_day3.py`: End-to-end smoke scenarios (`ST-01` through `ST-05`), including MITRE/report/PDF behavior.
- `docs/TEAM_EXECUTION_GUIDE.md`: Team ownership model, integration order, smoke pack.
- `docs/ROLE_HANDOFF_CHECKLIST.md`: Deliverables and acceptance gates per role.
- `docs/RUN_GUIDE.md`: Local run and smoke commands.
- `docs/API_REFERENCE.md`: Runtime contract documentation for API/WS.

## 7. Complexity Ladder Summary

1. Level 0 (Basic wiring): each P builds independently with mocks and frozen schemas.
2. Level 1 (Module correctness): each role has focused tests for local logic.
3. Level 2 (Integration correctness): backend ingestion merges P1 and P2 into P3 alert/report payloads.
4. Level 3 (Product flow): P4 consumes live backend contracts and replay timeline for full demo narrative.
5. Level 4 (Operational confidence): full test packs (`tests/`) validate the cross-role flow continuously.

## 8. Quick Mapping (Who owns what)

- P1 owns: `ml/`
- P2 owns: `graph/`
- P3 owns: `backend/`
- P4 owns: `frontend/`
- Shared quality/integration owns: `tests/` and `docs/`
