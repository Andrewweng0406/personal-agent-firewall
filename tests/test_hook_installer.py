from __future__ import annotations

import json

from integrations.hook_installer import doctor, install, uninstall


def test_install_preserves_existing_config_and_is_idempotent(tmp_path):
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "permissions": {"allow": ["Read"]},
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "echo existing"}],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    first = install("claude", path)
    second = install("claude", path)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert set(first["added"]) == {
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "Stop",
    }
    assert first["backup"] is not None
    assert second["added"] == []
    assert second["backup"] is None
    assert data["permissions"] == {"allow": ["Read"]}
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "echo existing"
    assert doctor("claude", path)["installed"] is True


def test_uninstall_removes_only_firewall_entries(tmp_path):
    path = tmp_path / ".codex" / "hooks.json"
    install("codex", path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["hooks"]["PreToolUse"].insert(
        0,
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "echo keep-me"}],
        },
    )
    path.write_text(json.dumps(data), encoding="utf-8")

    result = uninstall("codex", path)
    remaining = json.loads(path.read_text(encoding="utf-8"))

    assert "PreToolUse" in result["removed"]
    assert remaining["hooks"]["PreToolUse"] == [
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "echo keep-me"}],
        }
    ]
    assert doctor("codex", path)["installed"] is False


def test_doctor_reports_missing_config(tmp_path):
    result = doctor("claude", tmp_path / "missing.json")

    assert result["installed"] is False
    assert "PreToolUse" in result["missing"]
