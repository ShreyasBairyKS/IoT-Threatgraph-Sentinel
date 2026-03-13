# IoT ThreatGraph Sentinel - Team Execution Guide (4 People, 7 Days)

This guide is the source of truth for parallel execution. It is designed to remove role confusion, prevent integration churn, and maximize delivery speed for a 4-person team.

---

## Table of Contents

1. [Execution Principles](#1-execution-principles)
2. [Team Ownership Matrix](#2-team-ownership-matrix)
3. [Parallel Build Architecture](#3-parallel-build-architecture)
4. [Data and Event Contracts (Freeze on Day 1)](#4-data-and-event-contracts-freeze-on-day-1)
5. [Branch and Merge Strategy](#5-branch-and-merge-strategy)
6. [Day-by-Day Delivery Plan](#6-day-by-day-delivery-plan)
7. [Definition of Done by Role](#7-definition-of-done-by-role)
8. [Integration Playbook (Day 4)](#8-integration-playbook-day-4)
9. [Risk Management and Fallbacks](#9-risk-management-and-fallbacks)
10. [Demo and Judge Readiness Checklist](#10-demo-and-judge-readiness-checklist)

---

## 1. Execution Principles

- One person owns one domain end-to-end.
- API and schema contracts are frozen on Day 1.
- Mock-first development is mandatory for parallel speed.
- No direct edits across another person's owned module without explicit approval.
- Daily integration window is required (minimum 45 minutes).
- Every feature must be demoable independently before full integration.

---

## 2. Team Ownership Matrix

| Person | Role | Owns | Must Deliver |
|---|---|---|---|
| P1 | Data and ML | Feature extraction, anomaly scoring, SHAP reasons, model artifacts | Versioned models + scoring API module + reason strings |
| P2 | Graph and Threat Intelligence | Graph construction, propagation risk, MITRE mapping, next-target prediction | Graph service module + MITRE mapper + propagation outputs |
| P3 | Backend Platform | FastAPI, WebSocket event bus, incident report generator, PDF export | Stable REST and WS contracts + report pipeline |
| P4 | Frontend Product | React dashboard, Cytoscape graph, timeline replay, drill-down UI | Real-time dashboard with replay + alert and evidence views |

### Explicit Non-Ownership Rules

- P1 does not edit frontend chart logic.
- P2 does not edit ML model training logic.
- P3 does not redesign UI components.
- P4 does not change backend payload shapes unilaterally.

---

## 3. Parallel Build Architecture

Use this one-way flow and never bypass layers:

```
Dataset Replay
    -> P1 Feature Pipeline
    -> P1 Scoring Output
    -> P2 Propagation and MITRE Enrichment
    -> P3 API and Event Packaging
    -> P4 Dashboard Rendering and Replay UI
```

### Runtime Components

- `ml-worker` (P1): batch and streaming score generation.
- `graph-worker` (P2): risk propagation and path tracing.
- `api-server` (P3): REST endpoints + WebSocket broadcaster + report generation.
- `web-client` (P4): dashboard and interaction layer.

---

## 4. Data and Event Contracts (Freeze on Day 1)

All four members must sign off these payloads on Day 1 and freeze them.

### 4.1 Feature Window Contract (P1 -> P2/P3)

```json
{
  "window_start": "2026-03-11T10:00:00Z",
  "window_end": "2026-03-11T10:01:00Z",
  "device_id": "cam-001",
  "features": {
    "flow_duration_mean": 1.24,
    "packet_rate": 52.1,
    "byte_volume": 81234,
    "port_entropy": 2.18,
    "unique_dest_ips": 9,
    "tcp_ratio": 0.64,
    "udp_ratio": 0.35,
    "iat_mean": 0.092,
    "iat_std": 0.031
  }
}
```

### 4.2 Anomaly Result Contract (P1 -> P2/P3)

```json
{
  "timestamp": "2026-03-11T10:01:00Z",
  "device_id": "cam-001",
  "device_type": "camera",
  "scores": {
    "isolation_forest": 78.4,
    "autoencoder": 64.2,
    "final_risk": 73.1,
    "confidence": "high"
  },
  "reason_codes": [
    "outbound_volume_spike",
    "dest_ip_diversity_jump"
  ],
  "explanations": [
    "Outbound traffic is 6.8x above rolling baseline",
    "Unique destination IP count increased from 2 to 9"
  ]
}
```

### 4.3 Graph Enrichment Contract (P2 -> P3/P4)

```json
{
  "timestamp": "2026-03-11T10:01:05Z",
  "source_device": "cam-001",
  "propagation_risk": 0.81,
  "neighbors": ["router-02", "nvr-01", "sensor-07"],
  "next_target_prediction": [
    {"device_id": "router-02", "score": 0.88, "why": "high betweenness centrality"},
    {"device_id": "nvr-01", "score": 0.79, "why": "frequent bidirectional flow"}
  ],
  "attack_paths": [
    ["cam-001", "router-02", "access-ctrl-01"]
  ],
  "mitre": {
    "tactic": "Lateral Movement",
    "technique": "T1021"
  }
}
```

### 4.4 Alert Event Contract (P3 -> P4 over WebSocket)

```json
{
  "event_type": "alert.created",
  "event_id": "evt_4f20",
  "timestamp": "2026-03-11T10:01:07Z",
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

### 4.5 Incident Report Contract (P3 output)

```json
{
  "report_id": "rep_001",
  "generated_at": "2026-03-11T10:02:00Z",
  "incident_summary": "Potential lateral movement initiated from cam-001",
  "affected_devices": ["cam-001", "router-02", "access-ctrl-01"],
  "evidence": {
    "risk_score": 87,
    "explanations": ["Outbound traffic spike", "Unusual destination fan-out"],
    "mitre": [{"tactic": "Lateral Movement", "technique": "T1021"}]
  },
  "recommendations": [
    "Isolate cam-001 into quarantine VLAN",
    "Block outbound connections to unseen external endpoints",
    "Run firmware integrity check on router-02"
  ]
}
```

---

## 5. Branch and Merge Strategy

### Branch Naming

- `main` - protected, demo-ready only.
- `dev` - integration branch.
- `feature/p1-ml-engine`
- `feature/p2-graph-intel`
- `feature/p3-backend-platform`
- `feature/p4-frontend-dashboard`

### Merge Rules

- Direct push to `main` is forbidden.
- Every PR targets `dev` first.
- Minimum 1 reviewer from another role.
- Contract changes require all 4 approvals.
- Daily cut to `main` only after smoke test passes.

### Commit Convention

- `feat(p1): add isolation forest scoring pipeline`
- `feat(p3): add ws alert.created broadcaster`
- `fix(p4): normalize risk color thresholds`
- `docs(shared): freeze alert event schema`

---

## 6. Day-by-Day Delivery Plan

## Day 1 - Foundation and Contract Freeze

### All Team

- Confirm dataset paths and replay sample files.
- Freeze all JSON contracts in Section 4.
- Create repo skeleton and service boundaries.
- Define endpoint list and websocket event names.
- Set up CI checks: lint + tests + type checks.

### Day 1 Exit Criteria

- Contracts approved by all 4.
- Backend mocks available.
- Frontend can render from mock events.

## Day 2 - Independent Build Sprint

### P1

- Build feature extraction pipeline.
- Train and serialize Isolation Forest.
- Train and serialize device type classifier.

### P2

- Build graph constructor from flow events.
- Implement weighted PageRank propagation risk.
- Start MITRE ATTACK for ICS mapping table.

### P3

- Build FastAPI skeleton with `/devices`, `/alerts`, `/graph`, `/report`.
- Add websocket endpoint and mock publisher.
- Add contract validators with Pydantic models.

### P4

- Build three-panel dashboard skeleton.
- Add Cytoscape mock graph and risk color coding.
- Add alert feed and placeholder drill-down.

## Day 3 - Intelligence and Integration Readiness

### P1

- Add SHAP explanation generator.
- Add lightweight autoencoder drift detector.
- Emit final weighted risk with confidence label.

### P2

- Implement attack path tracing.
- Add next-target prediction ranking.
- Complete MITRE tagging outputs per alert.

### P3

- Connect P1 and P2 outputs to real API responses.
- Build incident JSON generator.
- Implement PDF export endpoint.

### P4

- Replace mocks with live websocket data.
- Add node click drill-down and trend charts.
- Add suspicious edge animation state.

## Day 4 - Full Integration Day

### All Team

- Execute replay -> score -> enrich -> push -> render pipeline.
- Fix payload mismatches immediately.
- Run integration smoke tests every 2 hours.
- Lock major architecture decisions by end of day.

## Day 5 - Showstopper Features

### P2 + P4

- Implement propagation replay timeline slider.
- Visualize node-by-node spread progression.

### P1 + P3

- Finalize one-click incident report PDF.
- Add recommendations and MITRE summary section.

### All Team

- Deploy to Render or Railway via Docker.

## Day 6 - Product Polish and Hardening

### All Team

- Improve visual polish and interaction smoothness.
- Stress test full replay with larger slices.
- Finalize README, architecture diagram, and setup steps.
- Record backup demo video.

## Day 7 - Pitch and Defense

### All Team

- Rehearse 5-minute demo twice.
- Prepare answers for ML explainability, propagation logic, and scalability.
- Freeze demo branch and fallback video path.

---

## 7. Definition of Done by Role

### P1 Done

- Model artifacts versioned and reproducible.
- Final risk score and confidence generated per window.
- SHAP explanations present for high-risk alerts.
- Unit tests for feature engineering and scoring pass.

### P2 Done

- Graph updates idempotent.
- Propagation score and next-target list generated.
- MITRE tags attached to every qualifying alert.
- Unit tests for propagation and path tracing pass.

### P3 Done

- Endpoints stable and documented.
- WebSocket event delivery latency under 1 second in local tests.
- Incident JSON and PDF generated from live alerts.
- API tests and contract tests pass.

### P4 Done

- Dashboard renders live alerts and graph updates without refresh.
- Replay slider controls attack timeline correctly.
- Device drill-down shows trend, reasons, and MITRE tags.
- Frontend tests pass and no critical UI errors.

---

## 8. Integration Playbook (Day 4)

### 8.1 Integration Order

1. P3 serves mock endpoints and WS stream.
2. P4 confirms UI compatibility with contract payloads.
3. P1 swaps mock scoring with real scoring output.
4. P2 injects graph enrichment and propagation data.
5. P3 enables report generation from final alert objects.

### 8.2 Smoke Test Pack

- `ST-01`: one normal device window -> no critical alert.
- `ST-02`: one anomalous device -> alert with explanations.
- `ST-03`: anomaly with neighbors -> propagation path shown.
- `ST-04`: MITRE tag appears in UI and report.
- `ST-05`: one-click PDF contains summary, evidence, recommendations.

### 8.3 Integration Freeze Rule

If a payload mismatch appears more than twice, stop feature work and fix schema alignment first.

---

## 9. Risk Management and Fallbacks

| Risk | Early Signal | Owner | Fallback |
|---|---|---|---|
| Autoencoder underperforms | No lift over Isolation Forest by Day 3 | P1 | Ship Isolation Forest only with strong SHAP explanations |
| MITRE mapping incomplete | Missing tags in over 20 percent alerts | P2 | Ship top 15 tactic-technique mappings manually curated |
| WebSocket instability | Delayed or dropped UI updates | P3 | Poll `/alerts` every 3 seconds as backup |
| Graph replay laggy on UI | FPS drops during slider playback | P4 | Reduce edge animation density and precompute replay frames |
| Deployment failure | Last-day infra issues | P3 | Pre-recorded local demo + localhost fallback |

---

## 10. Demo and Judge Readiness Checklist

- Propagation replay works with a clear attack story.
- Every major alert has MITRE context.
- Incident PDF generated in under 5 seconds.
- Dashboard clearly shows current risk and next likely target.
- Explainability text is understandable to non-ML judges.
- README includes architecture diagram, run commands, and known limits.
- Team can answer:
  - Why this ML stack?
  - How does confidence work?
  - How does propagation scoring work?
  - What happens at scale?

---

## Recommended Daily Cadence (Operational Discipline)

- 10:00-10:20: standup and blocker removal.
- 13:00-13:20: contract check and quick sync.
- 18:00-18:45: integration window and smoke tests.
- 22:00: push daily status in one line per owner: done, blocked, next.

This cadence is optional but strongly recommended for a 7-day build sprint.
