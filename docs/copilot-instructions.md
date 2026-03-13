# GitHub Copilot Instructions - IoT ThreatGraph Sentinel

This file defines how Copilot should work on this project so the team can build in parallel with minimal confusion.

---

## 1. Project Identity

IoT ThreatGraph Sentinel is an IoT threat detection and intelligence platform.

Core capabilities:

- anomaly detection from network traffic windows,
- propagation risk scoring on a device graph,
- MITRE ATT&CK for ICS tagging,
- real-time alert streaming to dashboard,
- one-click incident report generation (JSON and PDF).

---

## 2. Team Ownership Model (Hard Boundaries)

| Owner | Domain | Allowed Core Changes |
|---|---|---|
| P1 | Data and ML | Feature pipeline, model training/inference, SHAP explanations |
| P2 | Graph and Intelligence | Graph construction, propagation logic, MITRE mapping |
| P3 | Backend | FastAPI routes, websocket events, report generation |
| P4 | Frontend | React UI, Cytoscape rendering, replay timeline, UX polish |

Rules:

- Do not edit another owner's domain unless explicitly requested.
- Contract changes require team-wide sign-off.
- Keep modules decoupled and contract-driven.

---

## 3. Source-of-Truth Docs

Copilot must follow these files in order:

1. `docs/TEAM_EXECUTION_GUIDE.md`
2. `docs/ROLE_HANDOFF_CHECKLIST.md`
3. `docs/DATA_MODEL.md`
4. `docs/API_REFERENCE.md`
5. `docs/ARCHITECTURE.md`
6. `docs/IMPLEMENTATION.md`
7. `docs/RUN_GUIDE.md`

If a conflict exists, higher priority doc wins.

---

## 4. Coding and Design Standards

### General

- Prefer clear, small modules over large mixed files.
- Add type hints for all public function signatures.
- Use deterministic behavior for demo-critical paths.
- Keep comments short and useful (avoid obvious comments).

### API and Contracts

- Validate all payloads at API boundaries.
- Never silently change payload field names.
- New fields must be backward-compatible unless asked for breaking change.

### Error Handling

- Fail gracefully and return actionable errors.
- Include context-rich logs for model, graph, and stream failures.
- Never expose raw stack traces in API responses.

### Testing

- Add focused tests for any non-trivial logic change.
- For contract updates, include at least one contract validation test.

---

## 5. Domain-Specific Rules

### P1 (ML)

- Feature windows are immutable once emitted.
- Emit `final_risk` and `confidence` for every scored window.
- Explanations must be human-readable, not only code labels.

### P2 (Graph)

- Graph updates should be idempotent.
- Always return `attack_paths` and `next_target_prediction` when available.
- MITRE fields must include both tactic and technique id.

### P3 (Backend)

- Keep endpoint signatures aligned with `docs/API_REFERENCE.md`.
- Websocket event type names are stable, especially `alert.created`.
- Report output must include summary, evidence, and recommendations.

### P4 (Frontend)

- UI must handle missing optional fields without crashing.
- Graph interactions should remain usable on laptop screens.
- Replay timeline must be deterministic for demo playback.

---

## 6. Non-Negotiable Contract Fields

Copilot must preserve these fields:

- `device_id`
- `timestamp`
- `risk_score` (or `scores.final_risk` in ML payload)
- `confidence`
- `reasons` / `explanations`
- `mitre.tactic`
- `mitre.technique`

Do not rename these without explicit instruction.

---

## 7. Prompt Format for Best Results

Use this format whenever you ask Copilot to build or modify something.

## Standard Prompt Template

```text
Task: <what to build/fix>
Owner: <P1|P2|P3|P4|shared>
Goal: <expected outcome>
Inputs: <files, endpoints, payloads, data source>
Constraints: <must keep, must avoid>
Output: <exact deliverable: code/docs/tests>
Done When: <clear acceptance criteria>
```

## Quick Template (short tasks)

```text
Task: <single change>
Owner: <role>
Keep: <contracts or files that must not break>
Done When: <1-2 measurable checks>
```

## Debug Template

```text
Issue: <what is broken>
Where: <file/endpoint/component>
Expected: <correct behavior>
Actual: <current behavior>
Repro Steps: <1..n>
Constraints: <no schema changes / no UI changes / etc>
Done When: <test or behavior condition>
```

---

## 8. Good Prompt Examples

### Example A (P1)

```text
Task: Build feature extraction for 60-second windows from CIC-IoT-2023 flows
Owner: P1
Goal: Generate contract-compliant feature window JSON for scoring
Inputs: data/cic_sample.csv, docs/DATA_MODEL.md section Feature Window Schema
Constraints: Keep field names exactly as schema; no backend changes
Output: Python module + unit tests + sample output JSON
Done When: 100 sample windows generated and schema validation passes
```

### Example B (P3)

```text
Task: Implement websocket publisher for alert.created events
Owner: P3
Goal: Frontend receives live alert events in under 1 second
Inputs: docs/API_REFERENCE.md websocket section
Constraints: Do not modify existing REST payloads
Output: FastAPI websocket route + broadcaster service + test
Done When: Local test client receives 10/10 events with valid schema
```

---

## 9. Anti-Patterns to Avoid

- Do not propose architecture rewrites mid-sprint.
- Do not add heavy dependencies without explicit approval.
- Do not merge mock payload formats into production contracts.
- Do not mix ML training code into API route files.
- Do not introduce breaking field changes on Day 4+.

---

## 10. Delivery Style Expected from Copilot

When asked to implement:

- make actual file edits,
- summarize changed files and why,
- mention test status and any unverified parts,
- propose next action only if relevant.

This keeps the team moving fast and avoids ambiguity.
