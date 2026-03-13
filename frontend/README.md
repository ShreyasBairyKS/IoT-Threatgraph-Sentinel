# IoT ThreatGraph Sentinel Frontend (P4)

React + TypeScript dashboard for real-time alert monitoring.

## Prerequisites

- Node.js 20+
- Backend API running at `http://localhost:8000` (default)

## Install and Run

```bash
cd frontend
npm install
npm run dev
```

Default URL: `http://localhost:5173`

## Environment Variables

Create `frontend/.env` (optional):

```dotenv
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws/alerts
VITE_ENABLE_MOCK_FALLBACK=true
```

Behavior:

- Live mode: app connects to `VITE_WS_URL` and displays `Live WS` status.
- Mock fallback: if live APIs/WS are unavailable and `VITE_ENABLE_MOCK_FALLBACK=true`, app loads built-in mock data and displays `Mock WS`.
- Offline: if fallback is disabled and live backend is unavailable, app remains in offline state.

## Quick Smoke Check

1. Start backend (`uvicorn backend.main:app --reload --port 8000`).
2. Start frontend (`npm run dev`).
3. Open `http://localhost:5173` and confirm top bar shows `Live WS` after backend websocket connects.
