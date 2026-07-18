from pathlib import Path

import pytest

from app.gateway.tool_executor import ToolExecutionError, execute


def test_read_file_returns_contents(tmp_path):
    file_path = tmp_path / "note.txt"
    file_path.write_text("hello world")

    result = execute("read_file", {"path": str(file_path)})

    assert result == "hello world"


def test_read_file_missing_raises(tmp_path):
    with pytest.raises(ToolExecutionError):
        execute("read_file", {"path": str(tmp_path / "missing.txt")})


def test_read_file_unexpected_error_wraps_as_tool_execution_error(tmp_path, monkeypatch):
    file_path = tmp_path / "note.txt"
    file_path.write_text("hello world")

    def boom(self, encoding=None):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", boom)

    with pytest.raises(ToolExecutionError):
        execute("read_file", {"path": str(file_path)})


def test_write_file_creates_file_with_content(tmp_path):
    file_path = tmp_path / "out" / "note.txt"

    result = execute("write_file", {"path": str(file_path), "content": "hi there"})

    assert file_path.read_text() == "hi there"
    assert "Wrote" in result


def test_write_file_error_wraps_as_tool_execution_error(tmp_path, monkeypatch):
    file_path = tmp_path / "out" / "note.txt"

    def boom(self, content, encoding=None):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", boom)

    with pytest.raises(ToolExecutionError):
        execute("write_file", {"path": str(file_path), "content": "hi there"})


def test_write_file_parent_is_a_file_raises_tool_execution_error(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    file_path = blocker / "note.txt"

    with pytest.raises(ToolExecutionError):
        execute("write_file", {"path": str(file_path), "content": "hi there"})


def test_overwrite_file_uses_same_handler_as_write_file(tmp_path):
    file_path = tmp_path / "note.txt"
    file_path.write_text("old")

    execute("overwrite_file", {"path": str(file_path), "content": "new"})

    assert file_path.read_text() == "new"


def test_exec_python_returns_result_variable():
    result = execute("exec_python", {"code": "result = 1 + 1"})
    assert result == 2


def test_exec_python_error_raises_tool_execution_error():
    with pytest.raises(ToolExecutionError):
        execute("exec_python", {"code": "raise ValueError('boom')"})


def test_run_shell_returns_stdout():
    result = execute("run_shell", {"command": "echo hello"})
    assert result == "hello"


def test_run_shell_timeout_raises_tool_execution_error():
    # Use a short, test-local timeout (instead of the 10s default) so this
    # exercises the real subprocess.TimeoutExpired -> ToolExecutionError path
    # without slowing down the suite.
    with pytest.raises(ToolExecutionError):
        execute("run_shell", {"command": "sleep 2", "timeout": 0.1})


def test_run_shell_os_error_raises_tool_execution_error(monkeypatch):
    import subprocess

    def boom(*args, **kwargs):
        raise OSError("shell unavailable")

    monkeypatch.setattr(subprocess, "run", boom)

    with pytest.raises(ToolExecutionError):
        execute("run_shell", {"command": "echo hello"})


def test_search_web_returns_mock_string():
    result = execute("search_web", {"query": "cats"})
    assert "cats" in result


def test_execute_unknown_tool_raises():
    with pytest.raises(ToolExecutionError):
        execute("delete_universe", {})
