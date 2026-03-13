# IoT ThreatGraph Sentinel: ML, Graph, and Backend Complete Explanations

This document consolidates the full technical explanations for the three core modules:
- `ml/`
- `graph/`
- `backend/`

It is intended as a single reference for understanding what each file does, what models/algorithms are used, why they were chosen, and how data flows end-to-end.

---

## 1. `ml/` Folder: Complete Explanation

### 1.1 `ml/__init__.py`

**Purpose:**
- Package marker file.
- Makes `ml` importable as a Python package.

**Why it exists:**
- Required for clean module imports like `from ml.features import extract_features`.

---

### 1.2 `ml/requirements.txt`

**Dependencies:**
- `numpy>=1.26`
- `scikit-learn>=1.4`
- `shap` optional (commented)

**Why these are used:**
- `numpy`: feature vectors, matrix math, scoring transformations.
- `scikit-learn`: IsolationForest, RandomForestClassifier, StandardScaler, MLPRegressor.
- `shap` (optional): model explainability; if unavailable, fallback explanation logic is used.

---

### 1.3 `ml/features.py`

**Purpose:**
- Converts raw flow records into fixed-size per-device, per-window feature vectors.
- Produces the canonical 9-feature representation expected by training/inference.

**Core responsibilities:**
- Parse raw CSV safely.
- Group records into time windows (default 60s).
- Aggregate into robust statistical/network behavior features.
- Handle both raw flow records and pre-aggregated records.

**Key functions and why they exist:**
- `_safe_float(value, default=0.0)`
  - Prevents pipeline crashes due to missing/invalid numeric fields.
- `_entropy(counts)`
  - Computes Shannon entropy for destination-port diversity; useful for scanning behavior detection.
- `_std(values, mean)`
  - Computes dispersion for inter-arrival times (IAT variability).
- `extract_features(records)`
  - Main orchestrator: auto-detects format and routes to correct aggregation path.
- `_aggregate_raw(records)`
  - Builds the 9 canonical features from packet/flow level rows.
- `_aggregate_precomputed(records)`
  - Mean-pools already-computed features if source data is pre-aggregated.
- `build_windows(records, window_seconds=60)`
  - Time-bins records per device into 60-second windows.
- `load_csv(path)`
  - CSV loader utility for CLI usage.
- `_cli()`
  - Command-line entrypoint to produce feature-window output from a CSV input.

**Canonical 9 features:**
- `flow_duration_mean`
- `packet_rate`
- `byte_volume`
- `port_entropy`
- `unique_dest_ips`
- `tcp_ratio`
- `udp_ratio`
- `iat_mean`
- `iat_std`

**Why this feature set:**
- Captures both volumetric anomalies (bytes/rates) and behavioral anomalies (entropy, destination diversity, timing patterns, protocol mix).

---

### 1.4 `ml/train.py`

**Purpose:**
- Trains all model artifacts used by inference.
- Serializes model files into `artifacts/models/`.

**Models used and why:**
- **IsolationForest**
  - Unsupervised anomaly detector for tabular traffic behavior.
  - Good for scarce/noisy labels common in IoT threat detection.
- **RandomForestClassifier**
  - Supervised device-type classifier.
  - Helps infer/fill device type and provide context in output contracts.
- **MLPRegressor used as autoencoder surrogate**
  - Trained X -> X reconstruction.
  - Reconstruction error acts as drift/anomaly signal complementary to IsolationForest.
- **StandardScaler**
  - Normalizes feature magnitudes before model scoring to avoid dominance by high-scale fields.

**Key functions and why they exist:**
- `windows_to_matrix(windows)`
  - Converts list of feature dicts to fixed-order numpy matrix.
- `train_isolation_forest(X, random_state=42)`
  - Creates the primary anomaly model (`n_estimators=200`, contamination tuned).
- `isolation_forest_score(clf, X)`
  - Converts decision function output to a stable 0-100 risk scale.
- `train_device_classifier(X, device_types)`
  - Trains RandomForest + LabelEncoder for predicted device labels.
- `fit_scaler(X)`
  - Fits StandardScaler used by both IF and AE paths.
- `train_autoencoder(X)`
  - Trains MLP reconstruction model.
- `autoencoder_error(ae, X)`
  - Computes per-sample reconstruction MSE.
- `build_autoencoder_meta(errors)`
  - Creates calibration metadata (mean/std/p95) for robust score normalization.
- `save_artifact(obj, path)` / `load_artifact(path)`
  - Reusable pickle serialization helpers.
- `main()`
  - End-to-end training pipeline from prepared windows to artifact persistence.

**Output artifacts:**
- `isolation_forest.pkl`
- `device_classifier.pkl`
- `device_classes.pkl`
- `scaler.pkl`
- `autoencoder.pkl`
- `autoencoder_meta.pkl`

---

### 1.5 `ml/infer.py`

**Purpose:**
- Loads trained artifacts and performs production anomaly inference on each feature window.
- Produces contract-compliant scoring output for backend ingestion.

**Core pattern:**
- Build feature vector.
- Scale inputs.
- Score with IF and optional AE.
- Fuse scores into final risk.
- Predict/fill device type.
- Generate reason codes and explanations (SHAP when available, fallback heuristics otherwise).

**Key structures/functions:**
- `ModelBundle` dataclass
  - Typed container for loaded models/metadata.
- `load_models(model_dir)`
  - Loads all artifacts required for inference.
- `_feature_vector(features)`
  - Converts dict features into model-ready numpy array in canonical order.
- `_if_score(models, X_scaled)`
  - IsolationForest score mapped to 0-100.
- `_autoencoder_score(models, X_scaled)`
  - Reconstruction error score normalized with autoencoder metadata.
- `_predict_device_type(models, X_scaled, fallback)`
  - Predicts device type with RF; falls back if classifier unavailable.
- `_confidence(risk)`
  - `>=80` high, `>=50` medium, else low.
- `_reason_codes_and_explanations(...)`
  - Tries SHAP-based attribution first; otherwise z-score/rule-based diagnostics.
- `infer_window(models, *, device_id, device_type, features, timestamp)`
  - Main per-window inference API.
  - Score fusion: `0.7 * IF + 0.3 * AE` (or IF-only if AE unavailable).
- `main()`
  - Batch CLI from feature JSON input to anomaly JSON output.

**Why weighted fusion:**
- IF captures isolation-based outliers well.
- AE captures reconstruction drift patterns.
- Weighted combination reduces single-model blind spots.

---

### 1.6 `ml/score_window.py`

**Purpose:**
- Baseline Day-1 heuristic scorer used before full multi-model pipeline maturity.

**Main pieces:**
- `ScoreResult` dataclass
  - Holds score output and exposes `to_contract_payload()`.
- `_iso_utc_now()`
  - UTC timestamp helper.
- `score_features(device_id, device_type, features)`
  - Rule/log1p-based risk scoring heuristic.

**Why it still matters:**
- Useful as fallback/simple replay scoring.
- Keeps a deterministic lightweight path for demos and regression checks.

---

### 1.7 `ml/replay_score.py`

**Purpose:**
- Replays historical CSV data and emits anomaly-like JSON using the baseline scorer.

**Key functions:**
- `_to_float(x)`
  - Safe numeric parsing helper.
- `main()`
  - Reads CSV, groups by device, aggregates fields, scores with `score_features`, writes JSON.

**Why this exists:**
- Fast demonstration utility.
- Allows offline scoring without retraining or full live pipeline dependencies.

---

### 1.8 `ml/tests/`

**Files:**
- `test_features.py`
- `test_infer.py`
- `test_replay_score.py`
- `test_score_window.py`

**Purpose:**
- Validate extraction logic, scoring behavior, replay pipeline correctness, and payload/contract compatibility.

---

## 2. `graph/` Folder: Complete Explanation

### 2.1 `graph/requirements.txt`

**Dependencies:**
- `pydantic==2.4.2`
- `networkx==3.2.1`
- `pytest==7.4.3`
- `numpy==1.26.4`
- `scipy==1.11.4`

**Why these are used:**
- `networkx`: directed weighted graph modeling + PageRank.
- `pydantic`: strict contracts for P2 payloads.
- `numpy/scipy`: numerical backend used by ranking computations.
- `pytest`: unit test framework.

---

### 2.2 `graph/models.py`

**Purpose:**
- Defines P2 data models and shared contracts used when exchanging data with backend.

**Models included:**
- `FeatureWindow`
- `AnomalyScores`
- `AnomalyResult`
- `NextTargetPrediction`
- `MitreTag`
- `GraphEnrichment`

**Most important output model:**
- `GraphEnrichment`
  - `timestamp`
  - `source_device`
  - `propagation_risk`
  - `neighbors`
  - `next_target_prediction`
  - `attack_paths`
  - `mitre`

**Why model contracts are critical:**
- They guarantee that P2 outputs are immediately ingestible by `POST /ingest/graph` without schema negotiation.

---

### 2.3 `graph/build_graph.py`

**Purpose:**
- Builds a directed communication graph from flow CSV data.

**Algorithmic approach:**
- Nodes = devices/IPs.
- Directed edges (`src -> dst`) represent communication direction.
- Edge weight increments with repeated flows (frequency proxy).

**Key functions:**
- `build_graph_from_flows(csv_path)`
  - Reads flow rows and constructs weighted `nx.DiGraph`.
- `save_graph(G, output_path)`
  - Serializes graph to JSON (node-link format).
- `load_graph(input_path)`
  - Restores saved graph JSON to a live graph object.
- CLI `__main__`
  - Input CSV -> `artifacts/graph.json`.

**Why directed weighted graph:**
- Direction matters for attack movement.
- Weight captures communication strength and practical propagation likelihood.

---

### 2.4 `graph/propagation.py`

**Purpose:**
- Consumes graph + anomaly outputs and produces propagation intelligence.

**What it computes per anomalous device:**
- Propagation risk score.
- Top likely next targets.
- Candidate attack paths (limited depth traversal).
- MITRE ATT&CK mapping for analyst context.

**Key constants:**
- `MITRE_MAPPING`
  - Example mappings:
    - `outbound_volume_spike` -> Exfiltration / `T1048`
    - `dest_ip_diversity_jump` -> Lateral Movement / `T1021`
- `DEFAULT_MITRE`
  - Fallback tag when no reason code mapping exists.

**Key functions:**
- `calculate_propagation_risk(G, anomalous_node, base_risk)`
  - Uses personalized PageRank seeded on anomalous node.
  - Returns `propagation_risk` and ranked `next_targets`.
- `trace_attack_paths(G, start_node, depth=2)`
  - DFS/BFS-style traversal to generate potential attack paths.
  - Avoids loops and limits depth for tractability.
- `map_mitre_tags(reason_codes)`
  - Maps P1 reason codes to MITRE tags.
- `process_anomalies(graph_path, scores_path, output_path)`
  - Full orchestration:
    - load graph
    - load anomaly results
    - validate as `AnomalyResult`
    - compute enrichment
    - write `artifacts/graph_enrichment.json`

**Why personalized PageRank:**
- Captures influence/reachability from the anomalous node over weighted directed topology.
- Better than local degree-only metrics for network propagation potential.

---

### 2.5 `graph/tests/test_propagation.py`

**Purpose:**
- Verifies correctness of propagation logic.

**Tests include:**
- `test_calculate_propagation_risk`
  - Ensures score range validity and reasonable next-target ordering.
- `test_trace_attack_paths`
  - Ensures expected multi-hop paths are discovered.
- `test_map_mitre_tags`
  - Ensures known reason codes map correctly and unknown codes fall back.

---

## 3. `backend/` Folder: Complete Explanation

### 3.1 `backend/__init__.py`

**Purpose:**
- Package marker for backend module imports.

---

### 3.2 `backend/config.py`

**Purpose:**
- Environment-driven application settings (`BaseSettings`).

**Important fields:**
- app identity/version
- WebSocket mock interval
- polling fallback interval
- PDF timeout
- in-memory alert store capacity

**Why centralized config:**
- keeps operational settings in one place
- supports `.env` overrides without code edits

---

### 3.3 `backend/contracts.py`

**Purpose:**
- Canonical contract definitions across P1/P2/P3/P4.

**Major models:**
- `FeatureWindow`
- `AnomalyScores`
- `AnomalyResult`
- `NextTargetPrediction`
- `MITRETag`
- `GraphEnrichment`
- `AlertGraph`
- `AlertEvent`
- `IncidentEvidence`
- `IncidentReport`
- `DeviceSummary`

**Why this file is foundational:**
- All routers, stores, and frontend type expectations depend on these schemas.
- Contract validation catches integration errors at runtime boundary.

---

### 3.4 `backend/store.py`

**Purpose:**
- Async-safe in-memory state store and merge logic.

**Key constant:**
- `ALERT_RISK_THRESHOLD = 60.0`

**Helper:**
- `_risk_to_severity(score)`
  - maps numeric risk into low/medium/high/critical bands.

**Classes and responsibilities:**
- `AlertStore`
  - rolling deque of recent alerts (bounded by `MAX_ALERT_STORE`).
- `DeviceRegistry`
  - latest `DeviceSummary` per `device_id`.
- `GraphStore`
  - latest `GraphEnrichment` snapshot.

**Merge function:**
- `build_alert_event(anomaly, graph=None)`
  - combines P1 anomaly and optional P2 graph data into a P4-ready `AlertEvent`.
  - creates event_id, severity, path, next targets, mitre payload.

**Singletons:**
- `alert_store`
- `device_registry`
- `graph_store`

**Why this architecture:**
- Enables immediate day-2/day-3 integration without external DB dependency.
- Provides deterministic shared state for all endpoint handlers.

---

### 3.5 `backend/main.py`

**Purpose:**
- FastAPI entrypoint and application wiring.

**What it configures:**
- App metadata (title/version/description).
- CORS middleware (`*` in dev mode).
- Router registration:
  - `/devices`
  - `/alerts`
  - `/graph`
  - `/report`
  - `/ingest`
- Health endpoint:
  - `GET /health` returns status + version.
- WebSocket route:
  - `/ws/alerts`
- Lifespan startup task:
  - starts `mock_broadcast_loop()`.

**Why lifespan task exists:**
- Ensures P4 gets immediate live-stream behavior even before real ingest data arrives.

---

### 3.6 `backend/routers/devices.py`

**Endpoint:** `GET /devices`

**Purpose:**
- Return latest per-device status/risk summaries.

**Data source behavior:**
- live: `device_registry.get_all()`
- fallback: `MOCK_DEVICES` if live store empty

**Why fallback:**
- frontend remains demo-ready from day 1.

---

### 3.7 `backend/routers/alerts.py`

**Endpoints:**
- `GET /alerts`
- `GET /alerts/{event_id}`

**Purpose:**
- list all alerts newest-first
- fetch single alert for drill-down panel

**Data source behavior:**
- live store first
- mock fallback if empty/not found
- 404 if not found in either source for by-id route

---

### 3.8 `backend/routers/graph.py`

**Endpoint:** `GET /graph`

**Purpose:**
- return latest graph enrichment snapshot used by frontend graph panels.

**Data source behavior:**
- live `graph_store.get()`
- fallback `MOCK_GRAPH`

---

### 3.9 `backend/routers/ingest.py`

**Endpoints:**
- `POST /ingest/anomaly` (P1 -> P3)
- `POST /ingest/graph` (P2 -> P3)

**`POST /ingest/anomaly` flow:**
- Accept `AnomalyResult`.
- Return `202 Accepted` quickly.
- Process in background:
  - update `DeviceRegistry`
  - if risk >= threshold:
    - merge with latest graph snapshot
    - build `AlertEvent`
    - store in `AlertStore`
    - broadcast via WebSocket `manager.broadcast(...)`

**`POST /ingest/graph` flow:**
- Accept `GraphEnrichment`.
- update `GraphStore` with latest snapshot.

**Why background tasks:**
- non-blocking ingestion latency for producer services (P1/P2).

---

### 3.10 `backend/routers/report.py`

**Endpoints:**
- `POST /report`
- `GET /report/{event_id}/pdf`

**`POST /report`:**
- Accepts full `AlertEvent` payload.
- Returns `IncidentReport` JSON from `build_report()`.

**`GET /report/{event_id}/pdf`:**
- Looks up alert from `AlertStore`.
- builds report.
- renders PDF bytes via `export_pdf()`.
- returns `application/pdf` attachment response.

**Why this split:**
- JSON report path for API/UI display.
- PDF path for downloadable executive artifacts.

---

### 3.11 `backend/ws/broadcaster.py`

**Purpose:**
- Manages WebSocket clients and event broadcasting.

**Class:** `ConnectionManager`
- tracks active connections
- connect/disconnect lifecycle
- broadcast to all clients
- targeted send helper

**Functions:**
- `ws_alert_endpoint(websocket)`
  - accepts connection
  - sends latest mock alert immediately
  - keeps socket alive and handles disconnect cleanly
- `mock_broadcast_loop()`
  - periodically cycles `MOCK_ALERTS` and broadcasts them
  - driven by `WS_MOCK_INTERVAL_SECONDS`

**Why this design:**
- cleanly separates transport concerns from ingest logic.
- real ingest pipeline can call the same broadcast manager.

---

### 3.12 `backend/reporting/generate_report.py`

**Purpose:**
- Builds `IncidentReport` objects from `AlertEvent` input.

**Key function:** `build_report(alert)`
- composes evidence
- derives affected device chain
- builds incident summary text
- generates recommendations

**Recommendation helper:** `_generate_recommendations(alert)`
- rule-based response guidance:
  - quarantine for high risk
  - block suspicious outbound traffic
  - monitor predicted next targets
  - run firmware integrity checks along attack path

**Why rule-based here:**
- deterministic and interpretable output for judges/operators.

---

### 3.13 `backend/reporting/export_pdf.py`

**Purpose:**
- Converts `IncidentReport` into a styled PDF (ReportLab).

**Layout includes:**
- branded header
- metadata table (report id/time/devices)
- incident summary section
- evidence table (risk, MITRE, findings)
- recommendations bullets
- confidentiality footer

**Key function:** `export_pdf(report) -> bytes`
- renders in-memory using `io.BytesIO`
- returns raw PDF bytes for HTTP response

**Why in-memory rendering:**
- no temporary files
- simpler deployment/runtime behavior

---

### 3.14 `backend/mocks/mock_store.py`

**Purpose:**
- Provides contract-valid mock payloads for all key endpoint types.

**Exports include:**
- `MOCK_DEVICES`
- `MOCK_ALERTS`
- `MOCK_GRAPH`
- (and report/evidence-related sample structures)

**Why this file is important:**
- decouples frontend progress from backend ingest readiness.
- ensures all mock payloads stay aligned with Pydantic contracts.

---

## 4. End-to-End Pipeline Summary (ML -> Graph -> Backend -> Frontend)

1. **ML (`ml/`)**
   - feature extraction from raw flows
   - model scoring (IF + AE) -> final risk, confidence, reasons
   - emits anomaly JSON (`AnomalyResult`)

2. **Graph (`graph/`)**
   - builds communication topology
   - computes propagation risk + next targets + attack paths + MITRE mapping
   - emits enrichment JSON (`GraphEnrichment`)

3. **Backend (`backend/`)**
   - ingests anomaly and graph payloads
   - updates in-memory live state
   - merges into `AlertEvent` when threshold breached
   - serves REST + WebSocket + report/PDF outputs

4. **Frontend (P4)**
   - consumes `/devices`, `/alerts`, `/graph`
   - listens to `/ws/alerts` for real-time event updates
   - requests `/report` and `/report/{event_id}/pdf` for incident reporting

---

## 5. Why This Architecture Works Well for Demo + Integration

- Contract-first schemas reduce integration friction.
- Mock fallbacks keep UI/endpoint workflows always demonstrable.
- Weighted model fusion improves robustness over single-model scoring.
- Graph enrichment transforms isolated anomaly flags into attack-propagation context.
- Background ingestion + WS broadcast provides near real-time alerting behavior.
- Report generation offers both machine-readable JSON and human-readable PDF outputs.

---

## 6. Quick Reference: Most Important Files

- ML core:
  - `ml/features.py`
  - `ml/train.py`
  - `ml/infer.py`

- Graph core:
  - `graph/build_graph.py`
  - `graph/propagation.py`
  - `graph/models.py`

- Backend core:
  - `backend/main.py`
  - `backend/contracts.py`
  - `backend/store.py`
  - `backend/routers/ingest.py`
  - `backend/ws/broadcaster.py`
  - `backend/reporting/generate_report.py`
  - `backend/reporting/export_pdf.py`
