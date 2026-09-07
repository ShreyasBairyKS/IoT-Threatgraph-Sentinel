"""
tests/test_ws_broadcaster.py - Coverage for the WebSocket delivery layer.

backend/ws/broadcaster.py had zero test coverage despite being the
real-time alert delivery path — including the broadcast-list mutation
race (a concurrent disconnect skipping a still-connected client) that was
fixed by iterating a snapshot instead of the live active_connections list.
These tests cover ConnectionManager directly (fast, deterministic, no real
ASGI socket needed) plus one end-to-end check of the /ws/alerts endpoint.
"""

from __future__ import annotations

from typing import Any, Callable

from fastapi.testclient import TestClient

from backend.main import app
from backend.ws.broadcaster import ConnectionManager

client = TestClient(app)


class _FakeWebSocket:
    """Minimal stand-in for fastapi.WebSocket — just enough for ConnectionManager."""

    def __init__(self, name: str, fail: bool = False, on_send: Callable[[], None] | None = None) -> None:
        self.name = name
        self.received: list[dict[str, Any]] = []
        self._fail = fail
        self._on_send = on_send

    async def send_json(self, payload: dict[str, Any]) -> None:
        if self._on_send:
            self._on_send()
        if self._fail:
            raise RuntimeError(f"{self.name} send failed")
        self.received.append(payload)


class TestConnectionManagerBroadcast:
    async def test_broadcast_delivers_to_all_connections(self):
        manager = ConnectionManager()
        a, b = _FakeWebSocket("a"), _FakeWebSocket("b")
        manager.active_connections = [a, b]

        await manager.broadcast({"event": "alert.created"})

        assert a.received == [{"event": "alert.created"}]
        assert b.received == [{"event": "alert.created"}]

    async def test_broadcast_removes_connection_that_fails_to_send(self):
        manager = ConnectionManager()
        good, bad = _FakeWebSocket("good"), _FakeWebSocket("bad", fail=True)
        manager.active_connections = [good, bad]

        await manager.broadcast({"event": "alert.created"})

        assert good.received == [{"event": "alert.created"}]
        assert good in manager.active_connections
        assert bad not in manager.active_connections

    async def test_broadcast_survives_concurrent_disconnect_mid_iteration(self):
        """
        Regression test for the mutation-during-iteration race: broadcast()
        must not skip a still-connected client when another client is
        removed from active_connections mid-broadcast (e.g. a concurrent
        WebSocketDisconnect firing on a different connection while this
        one's send is in flight).

        Before the fix (iterating self.active_connections directly instead
        of a list(...) snapshot), removing `b` from the live list while
        processing `a` shifted `c` into `b`'s slot and skipped `b` entirely
        for that broadcast — `b.received` would have stayed empty here.
        """
        manager = ConnectionManager()
        a, b, c = _FakeWebSocket("a"), _FakeWebSocket("b"), _FakeWebSocket("c")

        def disconnect_b_during_a_send() -> None:
            manager.disconnect(b)

        a._on_send = disconnect_b_during_a_send
        manager.active_connections = [a, b, c]

        await manager.broadcast({"event": "alert.created"})

        assert a.received == [{"event": "alert.created"}]
        assert b.received == [{"event": "alert.created"}]
        assert c.received == [{"event": "alert.created"}]
        # b was removed by the callback itself, not left dangling by broadcast.
        assert b not in manager.active_connections

    async def test_disconnect_is_safe_to_call_twice(self):
        manager = ConnectionManager()
        ws = _FakeWebSocket("solo")
        manager.active_connections = [ws]

        manager.disconnect(ws)
        manager.disconnect(ws)  # must not raise

        assert manager.active_connections == []


class TestWebSocketAlertEndpoint:
    def test_new_connection_receives_the_most_recent_alert(self):
        """A client connecting to /ws/alerts should immediately receive the
        latest stored alert, not just future broadcasts."""
        payload = {
            "timestamp": "2026-03-13T06:00:00Z",
            "device_id": "ws-endpoint-test-device",
            "device_type": "camera",
            "scores": {
                "isolation_forest": 90.0,
                "autoencoder": 88.0,
                "final_risk": 90.0,
                "confidence": "high",
            },
            "reason_codes": ["outbound_volume_spike"],
            "explanations": ["Outbound traffic spiked well above baseline."],
        }
        response = client.post("/ingest/anomaly", json=payload)
        assert response.status_code == 202

        with client.websocket_connect("/ws/alerts") as websocket:
            received = websocket.receive_json()

        assert received["device_id"] == "ws-endpoint-test-device"
        assert received["event_type"] == "alert.created"
