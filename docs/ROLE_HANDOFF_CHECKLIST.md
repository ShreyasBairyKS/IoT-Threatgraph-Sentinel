# Role Handoff Checklist - IoT ThreatGraph Sentinel

Use this checklist to run parallel development with minimal blocking.

---

## P1 (Data and ML) -> Handoff to P3 and P4

### Required Artifacts

- `artifacts/models/isolation_forest.pkl`
- `artifacts/models/device_classifier.pkl`
- `artifacts/models/autoencoder.pt` (optional if quality is good)
- `artifacts/schemas/anomaly_result.schema.json`
- `ml/score_window.py` callable from backend

### Required Fields in Output

- `device_id`
- `timestamp`
- `device_type`
- `final_risk`
- `confidence`
- `explanations[]`

### Acceptance Before Merge

- Same input window always gives deterministic score (within tolerance).
- Inference for one device window < 150 ms on local machine.
- At least 2 explanation strings for high-risk alerts.

---

## P2 (Graph and Intelligence) -> Handoff to P3 and P4

### Required Artifacts

- `graph/build_graph.py`
- `graph/propagation.py`
- `graph/mitre_mapper.py`
- `artifacts/schemas/graph_enrichment.schema.json`

### Required Fields in Output

- `source_device`
- `propagation_risk`
- `attack_paths[][]`
- `next_target_prediction[]`
- `mitre.tactic`
- `mitre.technique`

### Acceptance Before Merge

- Propagation score updates when edge weights change.
- At least one attack path returned for seeded anomaly scenario.
- MITRE tag attached for all high-severity alerts.

---

## P3 (Backend Platform) -> Handoff to P4

### Required Endpoints

- `GET /devices`
- `GET /alerts`
- `GET /graph`
- `POST /report`
- `WS /ws/alerts`

### Required Artifacts

- `backend/contracts.py` (Pydantic models)
- `backend/reporting/generate_report.py`
- `backend/reporting/export_pdf.py`
- `openapi.json` export committed to docs if used in frontend typing

### Acceptance Before Merge

- WebSocket pushes alert events in < 1 second.
- Contract validation rejects malformed payloads.
- PDF report generated from a real alert payload.

---

## P4 (Frontend Product) -> Handoff to Team Demo Branch

### Required Views

- Device list with risk colors and confidence badges
- Graph view with suspicious edge highlight
- Alert feed with explanation text
- Device drill-down with trend chart
- Replay timeline slider

### Required Artifacts

- `frontend/src/types/contracts.ts`
- `frontend/src/components/ThreatGraph.tsx`
- `frontend/src/components/ReplayTimeline.tsx`
- `frontend/src/components/IncidentPanel.tsx`

### Acceptance Before Merge

- UI works with both mock and live websocket data.
- Clicking a node opens full context panel.
- Replay timeline updates graph state deterministically.

---

## Daily Handoff Protocol (All Roles)

1. Push branch before integration window.
2. Post one sample payload in team channel.
3. Post one known limitation.
4. Post one next-day dependency (if any).

If any owner misses items 2-4, handoff is considered incomplete.
