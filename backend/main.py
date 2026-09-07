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
from backend.live_stream import realtime_stream_loop
from backend.routers import devices, alerts, graph, report, metrics
from backend.routers import ingest
from backend.routers import feed as feed_router
from backend.ws.broadcaster import manager, ws_alert_endpoint, mock_broadcast_loop
from backend.ws.synthetic_stream import synthetic_stream_loop

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan: startup / shutdown tasks
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Start background tasks on server startup."""
    tasks: list[asyncio.Task[None]] = []

    # DEMO_MODE is the single switch for a real deployment: set it to false
    # to disable every synthetic/demo generator below at once, instead of
    # having to know to flip each individual *_STREAM_ENABLED flag.
    if not settings.DEMO_MODE:
        logger.info("DEMO_MODE disabled — no synthetic/demo data generators started.")
    else:
        if settings.REALTIME_STREAM_ENABLED:
            logger.info("Starting real-time stream feeder...")
            tasks.append(asyncio.create_task(realtime_stream_loop()))
        else:
            logger.info("Starting mock WebSocket broadcaster...")
            tasks.append(asyncio.create_task(mock_broadcast_loop()))

        if settings.SYNTHETIC_STREAM_ENABLED:
            logger.info("Starting synthetic stream (interval=%.1fs)...", settings.SYNTHETIC_STREAM_INTERVAL_SECONDS)
            tasks.append(asyncio.create_task(synthetic_stream_loop()))

    yield

    for task in tasks:
        task.cancel()
    logger.info("Background tasks stopped.")


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

# CORS: allow P4 frontend (any origin in dev mode). No cookie/session-based
# auth is used anywhere in this API, so allow_credentials stays False —
# combining a wildcard origin with allow_credentials=True would make
# CORSMiddleware reflect the request's Origin header, permitting any origin
# to make credentialed cross-site requests.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# REST routers
# ---------------------------------------------------------------------------

app.include_router(devices.router)
app.include_router(alerts.router)
app.include_router(feed_router.router)
app.include_router(graph.router)
app.include_router(report.router)
app.include_router(metrics.router)
app.include_router(ingest.router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    """Liveness probe. Returns status and app version."""
    return {"status": "ok", "version": settings.APP_VERSION}


@app.get("/", tags=["health"])
async def root() -> dict[str, str]:
    """Root endpoint with quick links to API docs and health check."""
    return {
        "message": "IoT ThreatGraph Sentinel API is running",
        "health": "/health",
        "docs": "/docs",
    }


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
