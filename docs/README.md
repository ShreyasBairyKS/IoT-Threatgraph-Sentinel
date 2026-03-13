# Docs Index - IoT ThreatGraph Sentinel

Start here. This file tells the team what to read, what to run, and what to execute first.

---

## 1. Read Order (Mandatory)

1. `docs/TEAM_EXECUTION_GUIDE.md`
2. `docs/ROLE_HANDOFF_CHECKLIST.md`
3. `docs/DATA_MODEL.md`
4. `docs/API_REFERENCE.md`
5. `docs/ARCHITECTURE.md`
6. `docs/IMPLEMENTATION.md`
7. `docs/RUN_GUIDE.md`
8. `docs/PROMPT_PLAYBOOK.md`
9. `docs/copilot-instructions.md`

If docs conflict, follow this order.

---

## 2. Day 1 Startup Workflow

1. Freeze contracts in `docs/DATA_MODEL.md` and `docs/API_REFERENCE.md`.
2. Assign owners (`P1`, `P2`, `P3`, `P4`) and branch names.
3. Run role-specific local commands from `docs/RUN_GUIDE.md`.
4. Use first task prompts from `docs/PROMPT_PLAYBOOK.md`.
5. End day with one payload sample per owner.

---

## 3. First Prompt Each Owner Should Run

- P1: Prompt `1) Feature extraction from raw flows`
- P2: Prompt `6) Build communication graph`
- P3: Prompt `11) FastAPI endpoint skeleton`
- P4: Prompt `16) Dashboard shell and layout`

Then move to the next prompt in each owner section.

---

## 4. Branch Naming

- `feature/p1-ml-engine`
- `feature/p2-graph-intel`
- `feature/p3-backend-platform`
- `feature/p4-frontend-dashboard`
- integration branch: `dev`
- protected demo branch: `main`

---

## 5. Day 1 Command Quickstart

## P1

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r ml/requirements.txt
python ml/train.py
```

## P2

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r graph/requirements.txt
python graph/build_graph.py --input data/sample_flows.csv
```

## P3

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

## P4

```bash
cd frontend
npm install
npm run dev
```

---

## 6. Daily Closing Checklist

- Push branch updates.
- Share one schema-valid sample payload.
- Log one blocker and one next dependency.
- Confirm next day prompt ids per owner.

---

## 7. Integration Day Rule

On Day 4, no new features before schema alignment and smoke tests pass.

Use prompt `21) Day 4 end-to-end integration` from `docs/PROMPT_PLAYBOOK.md`.
