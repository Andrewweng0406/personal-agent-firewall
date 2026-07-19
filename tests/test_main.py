import importlib
import json

from fastapi.testclient import TestClient


def _write_protected_paths(tmp_path):
    data = {
        "critical_paths": [
            {"path": "/src/index.html", "risk_level": "CRITICAL", "auto_backup": True},
            {"path": "/.env", "risk_level": "CRITICAL", "auto_backup": True},
        ],
        "allowed_tools": ["read_file", "search_web"],
        "blocked_tools": ["rm", "format", "flush_db"],
    }
    file_path = tmp_path / "protected_paths.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")
    return file_path


def test_app_boots_and_allows_low_risk_call(tmp_path, monkeypatch):
    monkeypatch.setenv("PROTECTED_PATHS_FILE", str(_write_protected_paths(tmp_path)))
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    import app.main as main_module

    importlib.reload(main_module)

    with TestClient(main_module.app) as client:
        response = client.post(
            "/api/tool_call",
            json={
                "tool_name": "search_web",
                "args": {"query": "hello"},
                "agent_id": "agent-1",
                "session_id": "s-1",
            },
        )

    assert response.status_code == 200
    assert response.json()["status"] == "allowed"


def test_websocket_alerts_endpoint_connects(tmp_path, monkeypatch):
    monkeypatch.setenv("PROTECTED_PATHS_FILE", str(_write_protected_paths(tmp_path)))
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    import app.main as main_module

    importlib.reload(main_module)

    with TestClient(main_module.app) as client:
        with client.websocket_connect("/ws/alerts") as websocket:
            websocket.close()


def test_health_reports_runtime_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("PROTECTED_PATHS_FILE", str(_write_protected_paths(tmp_path)))
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("FIREWALL_MODE", "observe")
    monkeypatch.delenv("SEMANTIC_PII_ENABLED", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    import app.main as main_module

    importlib.reload(main_module)

    with TestClient(main_module.app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["mode"] == "observe"
    assert response.json()["pending_reviews"] == 0
    assert response.json()["semantic_pii"] == "disabled"
