from app.state.containment import ContainmentStore


async def test_session_quarantine_only_matches_the_target_session(tmp_path):
    store = ContainmentStore(tmp_path / "audit.db")
    await store.init_db()
    await store.quarantine("session", "agent-1", "session-risk", "Attack chain")

    assert await store.get_active("agent-1", "session-risk") is not None
    assert await store.get_active("agent-1", "session-safe") is None
    assert await store.get_active("agent-2", "session-risk") is None


async def test_agent_quarantine_matches_every_agent_session_and_can_be_released(tmp_path):
    store = ContainmentStore(tmp_path / "audit.db")
    await store.init_db()
    await store.quarantine("agent", "agent-1", None, "Reviewer action")

    assert await store.get_active("agent-1", "session-a") is not None
    assert await store.get_active("agent-1", "session-b") is not None

    released = await store.release("agent", "agent-1", None)

    assert released is True
    assert await store.get_active("agent-1", "session-a") is None


async def test_list_active_can_filter_by_agent_and_session(tmp_path):
    store = ContainmentStore(tmp_path / "audit.db")
    await store.init_db()
    await store.quarantine("session", "agent-1", "session-1", "First")
    await store.quarantine("session", "agent-2", "session-2", "Second")

    results = await store.list_active("agent-2", "session-2")

    assert len(results) == 1
    assert results[0]["agent_id"] == "agent-2"
