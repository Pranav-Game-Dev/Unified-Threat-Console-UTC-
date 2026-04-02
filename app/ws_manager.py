"""
UTC — WebSocket Manager
app/ws_manager.py

Manages all active WebSocket connections from dashboard clients.
Provides:
  - connect / disconnect lifecycle
  - broadcast to all clients
  - send to a specific client
  - channel-based subscriptions
  - auto-cleanup of dead connections
"""

import asyncio
import json
import logging
import uuid
from typing import Any

from fastapi import WebSocket

log = logging.getLogger("utc.ws_manager")


class WebSocketManager:
    """
    Thread-safe (async-safe) manager for active WebSocket connections.

    Usage (from any module):
        from app.ws_manager import ws_manager
        await ws_manager.broadcast_json({"type": "ids_alert", "data": {...}})
    """

    def __init__(self):
        # Maps WebSocket → client_id
        self._connections: dict[WebSocket, str] = {}
        # Maps client_id → set of subscribed channels
        self._subscriptions: dict[str, set[str]] = {}
        self._lock = asyncio.Lock()

    # ── Connection lifecycle ───────────────────────────────────────────────────
    async def connect(self, websocket: WebSocket) -> str:
        """
        Accept a new WebSocket connection and register it.
        Returns the assigned client_id.
        """
        await websocket.accept()
        client_id = str(uuid.uuid4())[:8]
        async with self._lock:
            self._connections[websocket] = client_id
            self._subscriptions[client_id] = {"all"}  # subscribe to all by default
        log.info(f"WS connected: {client_id} (total: {len(self._connections)})")
        return client_id

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket from the active pool."""
        client_id = self._connections.pop(websocket, None)
        if client_id:
            self._subscriptions.pop(client_id, None)
            log.info(f"WS disconnected: {client_id} (remaining: {len(self._connections)})")

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    # ── Send helpers ───────────────────────────────────────────────────────────
    async def broadcast_json(self, data: dict[str, Any]) -> None:
        """
        Broadcast a JSON payload to ALL connected clients.
        Dead connections are silently removed.
        """
        if not self._connections:
            return

        payload = json.dumps(data, default=str)
        dead: list[WebSocket] = []

        for ws in list(self._connections.keys()):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)

    async def broadcast_to_channel(self, channel: str, data: dict[str, Any]) -> None:
        """
        Broadcast to clients subscribed to a specific channel
        (or to the 'all' channel which every client has by default).
        """
        if not self._connections:
            return

        payload = json.dumps(data, default=str)
        dead: list[WebSocket] = []

        for ws, client_id in list(self._connections.items()):
            subs = self._subscriptions.get(client_id, {"all"})
            if "all" in subs or channel in subs:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)

        for ws in dead:
            self.disconnect(ws)

    async def send_personal_json(self, data: dict[str, Any], websocket: WebSocket) -> bool:
        """
        Send a JSON payload to a single specific WebSocket.
        Returns False if the send failed (dead connection).
        """
        try:
            await websocket.send_text(json.dumps(data, default=str))
            return True
        except Exception as exc:
            log.debug(f"Personal WS send failed: {exc}")
            self.disconnect(websocket)
            return False

    # ── Subscription management ───────────────────────────────────────────────
    def subscribe(self, client_id: str, channel: str) -> None:
        """Add a channel subscription for a client."""
        if client_id in self._subscriptions:
            self._subscriptions[client_id].add(channel)

    def unsubscribe(self, client_id: str, channel: str) -> None:
        """Remove a channel subscription (cannot remove 'all')."""
        if client_id in self._subscriptions and channel != "all":
            self._subscriptions[client_id].discard(channel)

    # ── Convenience event emitters ────────────────────────────────────────────
    async def emit_network_event(self, event: dict) -> None:
        await self.broadcast_json({"type": "network_event", "data": event})

    async def emit_ids_alert(self, alert: dict) -> None:
        await self.broadcast_json({"type": "ids_alert", "data": alert})

    async def emit_log_entry(self, entry: dict) -> None:
        await self.broadcast_json({"type": "log_entry", "data": entry})

    async def emit_scanner_update(self, update: dict) -> None:
        await self.broadcast_json({"type": "scanner_update", "data": update})

    async def emit_file_event(self, event: dict) -> None:
        await self.broadcast_json({"type": "file_event", "data": event})

    async def emit_stats_update(self, stats: dict) -> None:
        """Periodic stats snapshot broadcast (used for dashboard summary cards)."""
        await self.broadcast_json({"type": "stats_update", "data": stats})


# ── Module-level singleton ────────────────────────────────────────────────────
# Import and use this directly in all modules and routers:
#   from app.ws_manager import ws_manager
ws_manager = WebSocketManager()
