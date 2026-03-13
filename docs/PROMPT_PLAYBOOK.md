# Prompt Playbook - IoT ThreatGraph Sentinel

Copy, paste, fill the placeholders, and run.

---

## Usage Rule

Use one prompt per task. Keep scope tight and measurable.

Format reminder:

```text
Task:
Owner:
Goal:
Inputs:
Constraints:
Output:
Done When:
```

---

## P1 Prompts (Data and ML)

## 1) Feature extraction from raw flows

```text
Task: Build 60-second feature extraction pipeline from network flow data
Owner: P1
Goal: Emit schema-compliant feature window payloads for each device
Inputs: data/cic_sample.csv, docs/DATA_MODEL.md (Feature Window Schema)
Constraints: Keep exact feature key names from schema; no backend route edits
Output: Python module + unit tests + sample JSON output in artifacts/
Done When: 100 windows are generated and pass schema validation
```

## 2) Isolation Forest training and inference

```text
Task: Train Isolation Forest and implement inference script
Owner: P1
Goal: Produce anomaly score per device window
Inputs: artifacts/features.parquet, docs/DATA_MODEL.md (Anomaly Result Schema)
Constraints: Deterministic outputs with fixed random seed
Output: train.py, infer.py, saved model in artifacts/models/
Done When: Inference runs on sample data and outputs valid anomaly payload JSON
```

## 3) Device type classifier

```text
Task: Train a device type classifier from traffic patterns
Owner: P1
Goal: Predict camera/router/access-controller labels per window
Inputs: labeled training split, existing feature vectors
Constraints: Do not change anomaly schema field names
Output: classifier module + model artifact + evaluation summary
Done When: Classifier outputs label and confidence for all sample windows
```

## 4) SHAP reason generation

```text
Task: Add SHAP-based explanation generation for high-risk windows
Owner: P1
Goal: Produce human-readable explanation strings for alerts
Inputs: trained anomaly model, scored windows
Constraints: Explanations must be plain English, not raw feature ids only
Output: explanation module + tests + sample reason text list
Done When: Each high-risk sample has at least 2 explanation strings
```

## 5) Optional autoencoder drift detector

```text
Task: Add lightweight autoencoder risk signal and combine with Isolation Forest
Owner: P1
Goal: Improve subtle anomaly detection without breaking existing pipeline
Inputs: feature windows, current scoring output
Constraints: Keep current final_risk field; include confidence update
Output: autoencoder module + score fusion logic + benchmark note
Done When: Final payload includes autoencoder score and fused risk output
```

---

## P2 Prompts (Graph and Intelligence)

## 6) Build communication graph

```text
Task: Construct device communication graph from flow events
Owner: P2
Goal: Generate nodes and weighted edges usable by propagation model
Inputs: flow logs, docs/DATA_MODEL.md (Graph Enrichment Schema)
Constraints: Stable node ids and deterministic edge generation
Output: graph builder module + sample graph JSON
Done When: Graph JSON includes all active devices and weighted edges
```

## 7) Propagation risk scoring

```text
Task: Implement weighted propagation risk scoring using centrality approach
Owner: P2
Goal: Score likely spread impact from anomalous source device
Inputs: graph output + anomaly result payloads
Constraints: Keep output fields exactly as graph enrichment schema
Output: propagation.py + tests + sample risk outputs
Done When: propagation_risk and neighbors are emitted for test scenarios
```

## 8) Attack path tracing

```text
Task: Implement attack path tracing from anomalous source to reachable devices
Owner: P2
Goal: Return likely attack paths for backend and frontend replay
Inputs: graph state and source device ids
Constraints: Path list must be reproducible for same input graph
Output: path tracing module + tests
Done When: attack_paths field contains ranked non-empty paths on seeded data
```

## 9) Next target prediction

```text
Task: Build next-target prediction ranking with short reasoning text
Owner: P2
Goal: Predict top devices likely to be compromised next
Inputs: graph centrality features + anomaly source context
Constraints: Include why text for each predicted target
Output: ranking module + sample output in schema format
Done When: next_target_prediction includes at least top 3 targets with reasons
```

## 10) MITRE ATT&CK for ICS mapper

```text
Task: Implement MITRE ATT&CK for ICS tagging logic for enriched alerts
Owner: P2
Goal: Attach tactic and technique id to each qualifying alert
Inputs: mapped behavior patterns, MITRE mapping table/json
Constraints: Emit both mitre.tactic and mitre.technique
Output: mitre_mapper module + mapping table + tests
Done When: All high-severity sample alerts include valid MITRE tags
```

---

## P3 Prompts (Backend)

## 11) FastAPI endpoint skeleton

```text
Task: Implement backend endpoints /devices /alerts /graph /report and /health
Owner: P3
Goal: Provide stable contract-compliant API surface for frontend integration
Inputs: docs/API_REFERENCE.md and docs/DATA_MODEL.md
Constraints: No breaking payload changes without explicit approval
Output: FastAPI route modules + pydantic schemas + API tests
Done When: All endpoints return valid responses and tests pass
```

## 12) WebSocket alert stream

```text
Task: Add websocket endpoint /ws/alerts with alert.created event stream
Owner: P3
Goal: Push live enriched alerts to frontend
Inputs: docs/API_REFERENCE.md websocket event contract
Constraints: Event payload must include required fields and stable event_type
Output: websocket handler + broadcaster service + integration test
Done When: Test client receives schema-valid events in real time
```

## 13) Integrate ML and graph outputs

```text
Task: Wire P1 anomaly output and P2 graph enrichment into API responses
Owner: P3
Goal: Serve fully enriched alert objects from backend
Inputs: artifacts/ml_scores.json, artifacts/graph_enrichment.json
Constraints: Preserve contract fields and timestamp ordering
Output: integration service + parsing/validation logic + tests
Done When: /alerts returns enriched alerts with MITRE and propagation fields
```

## 14) Incident report JSON generator

```text
Task: Build incident report generator from latest alert evidence
Owner: P3
Goal: Produce structured report JSON with summary, evidence, recommendations
Inputs: alert event payloads and mapping logic
Constraints: Output must match Incident Report Schema in docs/DATA_MODEL.md
Output: report generation module + tests
Done When: POST /report returns valid report JSON for sample event id
```

## 15) PDF report export

```text
Task: Add PDF export for incident reports
Owner: P3
Goal: Return downloadable PDF with key incident sections
Inputs: report JSON output
Constraints: Keep JSON output path unchanged; add PDF as optional format
Output: pdf export module + endpoint wiring + test
Done When: POST /report with format=pdf returns valid application/pdf response
```

---

## P4 Prompts (Frontend)

## 16) Dashboard shell and layout

```text
Task: Build 3-panel dashboard layout for devices, graph, and alerts
Owner: P4
Goal: Display core threat operations view with responsive layout
Inputs: docs/API_REFERENCE.md, mock event payloads
Constraints: Keep room for replay timeline and drill-down panel
Output: React page layout + base styles + smoke test
Done When: Desktop and laptop layouts render cleanly without overlap
```

## 17) Cytoscape threat graph

```text
Task: Implement Cytoscape graph view with node risk colors and weighted edges
Owner: P4
Goal: Visualize device network and suspicious paths clearly
Inputs: GET /graph response contract
Constraints: Graph must handle missing optional fields safely
Output: ThreatGraph component + style mapping + tests
Done When: Nodes and edges render correctly from real backend payload
```

## 18) Live alert feed from websocket

```text
Task: Replace mock alerts with live websocket-driven alert feed
Owner: P4
Goal: Show new alerts instantly without page refresh
Inputs: WS /ws/alerts event contract
Constraints: Keep local mock fallback mode for offline UI work
Output: websocket client hook + alert feed component updates
Done When: Incoming alert.created events appear in UI within 1 second
```

## 19) Device drill-down and trend chart

```text
Task: Build click-to-drill panel for selected device
Owner: P4
Goal: Show risk trend, explanations, MITRE tags, and next-target details
Inputs: selected node id + /alerts and /devices data
Constraints: No crashes on partial data
Output: drill-down panel + trend chart component + tests
Done When: Clicking any node opens populated detail panel
```

## 20) Propagation replay timeline

```text
Task: Implement replay timeline slider to animate attack spread over graph
Owner: P4
Goal: Deliver showstopper visual replay for demo
Inputs: graph replay frames and alert timestamps
Constraints: Deterministic playback; maintain smooth UI at medium graph size
Output: ReplayTimeline component + graph frame animator
Done When: Slider scrub updates graph state correctly at each frame
```

---

## Shared Integration Prompts

## 21) Day 4 end-to-end integration

```text
Task: Execute end-to-end integration from replay -> ML -> graph -> API -> UI
Owner: shared
Goal: Validate full working pipeline with real payloads
Inputs: all role outputs and docs/TEAM_EXECUTION_GUIDE.md integration section
Constraints: Fix schema mismatches before feature polishing
Output: integration fixes + smoke test report in markdown
Done When: One full incident replay completes and renders correctly in dashboard
```

## 22) Contract mismatch resolver

```text
Task: Detect and resolve payload contract mismatches across P1/P2/P3/P4
Owner: shared
Goal: Restore compatibility without breaking frozen fields
Inputs: sample payloads from all modules
Constraints: Keep non-negotiable field names unchanged
Output: patch set + compatibility notes
Done When: Schema validation passes for all handoff payloads
```

## 23) Demo stability hardening

```text
Task: Harden system for live demo reliability
Owner: shared
Goal: Reduce runtime surprises during pitch
Inputs: current integrated branch and replay script
Constraints: No major architecture changes
Output: stability fixes + fallback runbook note
Done When: Two consecutive full demo runs pass without manual patching
```

## 24) Performance quick pass

```text
Task: Profile and improve replay latency and websocket throughput
Owner: shared
Goal: Keep dashboard responsiveness under demo load
Inputs: replay dataset and timing logs
Constraints: Prioritize low-risk optimizations only
Output: performance patch + before/after metrics summary
Done When: End-to-end update latency stays within target budget
```

## 25) Final pre-pitch QA

```text
Task: Run final QA checklist for features, contracts, and demo script
Owner: shared
Goal: Ensure judge-facing reliability and narrative clarity
Inputs: docs/TEAM_EXECUTION_GUIDE.md and docs/ROLE_HANDOFF_CHECKLIST.md
Constraints: Only bug fixes, no scope expansion
Output: QA pass report + remaining known limitations
Done When: Checklist is fully complete with no critical blockers
```
