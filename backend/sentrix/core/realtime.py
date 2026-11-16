"""WebSocket broadcast hub for live dashboard updates.

Sync code (FastAPI threadpool endpoints, the agent pipeline) calls
``hub.publish(...)``; messages are scheduled on the server's event loop.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from fastapi import WebSocket

from sentrix.core.logging import get_logger

log = get_logger("realtime")


class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def _broadcast(self, message: dict[str, Any]) -> None:
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(message)
            except Exception:  # client went away
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def publish(self, kind: str, data: dict[str, Any]) -> None:
        if self.loop is None or not self.clients:
            return
        msg = {"type": kind, "ts": datetime.now(UTC).isoformat(), "data": data}
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self.loop:
            self.loop.create_task(self._broadcast(msg))
        else:
            asyncio.run_coroutine_threadsafe(self._broadcast(msg), self.loop)


hub = Hub()
