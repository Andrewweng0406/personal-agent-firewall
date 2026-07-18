from app.risk.cross_agent_correlation import detect_cross_agent_pattern


def test_no_signal_when_no_recent_events():
    signal = detect_cross_agent_pattern("agent-a", "write_file", {"path": "/project/.env"}, [])
    assert signal.correlated is False
    assert signal.score_delta == 0


def test_no_signal_when_only_same_agent_denied_recently():
    history = [
        {
            "agent_id": "agent-a",
            "tool_name": "write_file",
            "args_json": '{"path": "/project/.env"}',
            "decision": "denied",
        }
    ]
    signal = detect_cross_agent_pattern(
        "agent-a", "write_file", {"path": "/project/.env"}, history
    )
    assert signal.correlated is False


def test_no_signal_when_other_agent_targeted_different_asset():
    history = [
        {
            "agent_id": "agent-b",
            "tool_name": "write_file",
            "args_json": '{"path": "/project/src/index.html"}',
            "decision": "denied",
        }
    ]
    signal = detect_cross_agent_pattern(
        "agent-a", "write_file", {"path": "/project/.env"}, history
    )
    assert signal.correlated is False


def test_no_signal_when_other_agent_event_was_allowed_not_denied():
    history = [
        {
            "agent_id": "agent-b",
            "tool_name": "write_file",
            "args_json": '{"path": "/project/.env"}',
            "decision": "allowed",
        }
    ]
    signal = detect_cross_agent_pattern(
        "agent-a", "write_file", {"path": "/project/.env"}, history
    )
    assert signal.correlated is False


def test_correlated_when_different_agent_recently_denied_for_same_path():
    history = [
        {
            "agent_id": "agent-b",
            "tool_name": "write_file",
            "args_json": '{"path": "/project/.env"}',
            "decision": "denied",
        }
    ]
    signal = detect_cross_agent_pattern(
        "agent-a", "write_file", {"path": "/project/.env"}, history
    )
    assert signal.correlated is True
    assert signal.score_delta == 100
    assert signal.correlated_agent_ids == ["agent-b"]
    assert "cross_agent_correlation:coordinated_target" in signal.matched_rules
    assert "agent-b" in signal.explanation


def test_correlated_when_target_embedded_in_a_shell_command():
    history = [
        {
            "agent_id": "agent-b",
            "tool_name": "run_shell",
            "args_json": '{"command": "cat /project/.env"}',
            "decision": "denied_auto_contained",
        }
    ]
    signal = detect_cross_agent_pattern(
        "agent-a", "run_shell", {"command": "rm -f /project/.env"}, history
    )
    assert signal.correlated is True
    assert signal.correlated_agent_ids == ["agent-b"]


def test_deduplicates_repeat_offenders_into_one_entry():
    history = [
        {
            "agent_id": "agent-b",
            "tool_name": "write_file",
            "args_json": '{"path": "/project/.env"}',
            "decision": "denied",
        },
        {
            "agent_id": "agent-b",
            "tool_name": "write_file",
            "args_json": '{"path": "/project/.env"}',
            "decision": "denied",
        },
    ]
    signal = detect_cross_agent_pattern(
        "agent-a", "write_file", {"path": "/project/.env"}, history
    )
    assert signal.correlated_agent_ids == ["agent-b"]


def test_multiple_distinct_correlated_agents_are_all_captured():
    history = [
        {
            "agent_id": "agent-b",
            "tool_name": "write_file",
            "args_json": '{"path": "/project/.env"}',
            "decision": "denied",
        },
        {
            "agent_id": "agent-c",
            "tool_name": "write_file",
            "args_json": '{"path": "/project/.env"}',
            "decision": "denied",
        },
    ]
    signal = detect_cross_agent_pattern(
        "agent-a", "write_file", {"path": "/project/.env"}, history
    )
    assert set(signal.correlated_agent_ids) == {"agent-b", "agent-c"}


def test_no_signal_when_current_call_has_no_extractable_target():
    signal = detect_cross_agent_pattern("agent-a", "search_web", {"query": "cats"}, [])
    assert signal.correlated is False
