# Implementation Plan

This plan translates the 7-day schedule into concrete deliverables and acceptance criteria.

---

## Day 1 - Contract and Foundation

### Tasks

- Freeze payload schemas in `docs/DATA_MODEL.md`.
- Confirm API and websocket contracts in `docs/API_REFERENCE.md`.
- Create branch structure and CI checks.
- Validate dataset access paths for N-BaIoT and CIC-IoT-2023.

### Acceptance Criteria

- All four owners approve contracts.
- Mock backend endpoints are available.
- Frontend renders from mock events.

---

## Day 2 - Parallel Build Sprint I

### P1 (Data and ML)

- Build feature extraction for fixed windows.
- Train Isolation Forest and device classifier.
- Produce anomaly result payload from static replay.

### P2 (Graph and Intelligence)

- Build communication graph from flows.
- Implement weighted propagation score.
- Draft MITRE ATTACK for ICS mapping table.

### P3 (Backend)

- Implement `GET /devices`, `GET /alerts`, `GET /graph`, `POST /report` skeleton.
- Implement `WS /ws/alerts` mock stream.
- Add strict Pydantic contract validation.

### P4 (Frontend)

- Build dashboard shell and Cytoscape canvas.
- Add mock alert feed and risk color logic.
- Add initial device drill-down layout.

### Acceptance Criteria

- Each role demonstrates independent output with contract-compliant payloads.

---

## Day 3 - Parallel Build Sprint II

### P1

- Add SHAP explainability text generation.
- Add optional autoencoder and confidence output.
- Emit final weighted risk score.

### P2

- Implement attack-path tracing and next-target ranking.
- Attach MITRE tactic and technique tags.

### P3

- Replace mocks with real P1 and P2 data ingestion.
- Build incident JSON generator.
- Implement PDF generation path.

### P4

- Wire live websocket events to UI.
- Add suspicious edge animation and risk trend chart.
- Render MITRE tags and evidence panel.

### Acceptance Criteria

- Endpoints and UI work with real payloads, not mocks.

---

## Day 4 - Integration Gate (Critical)

### Tasks

- Run end-to-end replay pipeline every 2 hours.
- Fix all schema mismatches first, then logic bugs.
- Validate smoke tests:
  - normal traffic baseline,
  - anomaly detection,
  - propagation path visibility,
  - MITRE tags display,
  - report generation.

### Acceptance Criteria

- One full incident can be replayed from ingestion to dashboard and report.

---

## Day 5 - Differentiator Features

### Tasks

- Build propagation replay timeline (P2 + P4).
- Finalize one-click report PDF and recommendations (P1 + P3).
- Deploy dockerized stack to Render or Railway.

### Acceptance Criteria

- Replay and report are demo-ready in deployed environment.

---

## Day 6 - Hardening and Polish

### Tasks

- Improve UI clarity and interaction flow.
- Run stress replay and check latency targets.
- Finalize README and architecture diagram.
- Record backup demo video.

### Acceptance Criteria

- System is stable for at least one full scripted demo run without manual fixes.

---

## Day 7 - Pitch and Final Freeze

### Tasks

- Rehearse 5-minute demo twice.
- Prepare Q and A notes on ML choice, SHAP, propagation, and scalability.
- Freeze demo branch and contingency plan.

### Acceptance Criteria

- Team can run live demo and fallback demo without role confusion.

---

## Final Readiness Gate

The project is considered complete only if all items pass:

- Propagation replay works.
- MITRE labels are visible in alerts.
- One-click report JSON and PDF generation works.
- Dashboard receives live updates over websocket.
- Team handoff checklist in `docs/ROLE_HANDOFF_CHECKLIST.md` is fully checked.
