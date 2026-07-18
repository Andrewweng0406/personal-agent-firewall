from app.ws.manager import ConnectionManager


class FakeWebSocket:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.sent: list[str] = []
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def send_text(self, data: str):
        if self.fail:
            raise RuntimeError("connection closed")
        self.sent.append(data)


async def test_connect_accepts_and_registers():
    manager = ConnectionManager()
    ws = FakeWebSocket()

    await manager.connect(ws)

    assert ws.accepted is True
    assert ws in manager.connections


async def test_broadcast_sends_json_to_all_connections():
    manager = ConnectionManager()
    ws1 = FakeWebSocket()
    ws2 = FakeWebSocket()
    await manager.connect(ws1)
    await manager.connect(ws2)

    await manager.broadcast({"type": "new_alert", "request_id": "abc"})

    assert ws1.sent == ['{"type": "new_alert", "request_id": "abc"}']
    assert ws2.sent == ['{"type": "new_alert", "request_id": "abc"}']


async def test_broadcast_drops_stale_connections():
    manager = ConnectionManager()
    good = FakeWebSocket()
    bad = FakeWebSocket(fail=True)
    await manager.connect(good)
    await manager.connect(bad)

    await manager.broadcast({"type": "resolved", "request_id": "abc"})

    assert bad not in manager.connections
    assert good in manager.connections


async def test_disconnect_removes_connection():
    manager = ConnectionManager()
    ws = FakeWebSocket()
    await manager.connect(ws)

    manager.disconnect(ws)

    assert ws not in manager.connections
