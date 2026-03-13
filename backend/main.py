"""
main.py - FastAPI application entry point for the P3 api-server.

Registers all routers, mounts the WebSocket endpoint, and starts the
mock broadcaster background task on startup.

Run locally:
    uvicorn backend.main:app --reload --port 8000

P3-owned endpoints:
    GET  /health
    GET  /devices
    GET  /alerts
    GET  /graph
    POST /report
    WS   /ws/alerts
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.routers import devices, alerts, graph, report
from backend.routers import ingest
from backend.ws.broadcaster import manager, ws_alert_endpoint, mock_broadcast_loop

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan: startup / shutdown tasks
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Start the mock WS broadcaster on server startup."""
    logger.info("Starting mock WebSocket broadcaster...")
    broadcast_task = asyncio.create_task(mock_broadcast_loop())
    yield
    broadcast_task.cancel()
    logger.info("Mock broadcaster stopped.")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "IoT ThreatGraph Sentinel — P3 Backend Platform.\n\n"
        "Provides REST endpoints and a WebSocket event bus for real-time "
        "alert streaming. Contract schemas are frozen per Section 4 of "
        "docs/TEAM_EXECUTION_GUIDE.md."
    ),
    lifespan=lifespan,
)

# CORS: allow P4 frontend (any origin in dev mode)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# REST routers
# ---------------------------------------------------------------------------

app.include_router(devices.router)
app.include_router(alerts.router)
app.include_router(graph.router)
app.include_router(report.router)
app.include_router(ingest.router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    """Liveness probe. Returns status and app version."""
    return {"status": "ok", "version": settings.APP_VERSION}


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    """
    WS /ws/alerts

    Real-time alert event stream. Clients receive `alert.created` events
    conforming to contract 4.4 in docs/TEAM_EXECUTION_GUIDE.md.
    """
    await ws_alert_endpoint(websocket)
