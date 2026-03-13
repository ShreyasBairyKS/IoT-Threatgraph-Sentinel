"""
ws/broadcaster.py - WebSocket endpoint and mock alert broadcaster.

Implements:
  - WS /ws/alerts : clients connect and receive alert.created events
  - Mock broadcaster: periodically pushes contract-compliant events
    so P4 can test live rendering from Day 1

Day 3: real alert events will be pushed by the ingestion pipeline
instead of the mock loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from fastapi import WebSocket, WebSocketDisconnect

from backend.config import settings
from backend.mocks.mock_store import MOCK_ALERTS

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages the set of active WebSocket connections."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WS client connected. Total: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info("WS client disconnected. Total: %d", len(self.active_connections))

    async def broadcast(self, payload: dict[str, Any]) -> None:
        """Send payload to all connected clients. Remove dead connections."""
        dead: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)

    async def send_personal(self, websocket: WebSocket, payload: dict[str, Any]) -> None:
        await websocket.send_json(payload)


# Singleton manager shared across the application lifecycle
manager = ConnectionManager()


async def ws_alert_endpoint(websocket: WebSocket) -> None:
    """
    WS /ws/alerts handler.

    On connect: immediately sends the latest mock alert so P4 sees
    something right away.
    Then stays open for the duration of the connection.
    """
    await manager.connect(websocket)
    try:
        # Send the most recent live alert immediately upon connection.
        # Fallback to mock alert only when no live alert exists yet.
        from backend.store import alert_store

        live_alerts = await alert_store.get_all()
        if live_alerts:
            await manager.send_personal(websocket, live_alerts[0].model_dump(mode="json"))
        elif MOCK_ALERTS:
            latest = MOCK_ALERTS[0].model_dump(mode="json")
            await manager.send_personal(websocket, latest)

        # Keep connection alive; real pushes come from broadcast()
        while True:
            # We wait for any client message (ping / pong / close)
            data = await websocket.receive_text()
            logger.debug("WS message received from client: %s", data)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def mock_broadcast_loop() -> None:
    """
    Background task that cycles through MOCK_ALERTS and broadcasts one
    every WS_MOCK_INTERVAL_SECONDS seconds.

    Activated at startup. Day 3: this loop is replaced by real event pushes
    from the ingestion pipeline calling manager.broadcast() directly.
    """
    index = 0
    while True:
        await asyncio.sleep(settings.WS_MOCK_INTERVAL_SECONDS)
        if manager.active_connections and MOCK_ALERTS:
            alert = MOCK_ALERTS[index % len(MOCK_ALERTS)]
            payload = alert.model_dump(mode="json")
            await manager.broadcast(payload)
            logger.debug("Mock broadcast sent: %s", alert.event_id)
            index += 1
