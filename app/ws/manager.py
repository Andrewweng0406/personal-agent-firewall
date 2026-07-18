from __future__ import annotations

import json


class ConnectionManager:
    def __init__(self):
        self._connections: list = []

    @property
    def connections(self) -> list:
        return list(self._connections)

    async def connect(self, websocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        payload = json.dumps(message)
        stale = []
        for connection in self._connections:
            try:
                await connection.send_text(payload)
            except Exception:
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)
