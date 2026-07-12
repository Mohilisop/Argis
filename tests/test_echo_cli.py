from __future__ import annotations

import json

from typer.testing import CliRunner

from argis.entrypoint import app


runner = CliRunner()


def test_echo_requires_two_snapshots(monkeypatch):
    monkeypatch.setattr("argis.entrypoint.load_history", lambda username: [])
    result = runner.invoke(app, ["echo", "alice"])
    assert result.exit_code == 1
    assert "at least two saved scans" in result.stdout


def test_echo_prints_coordinated_event(monkeypatch):
    history = [
        {
            "timestamp": "2026-07-10T10:00:00+00:00",
            "results": {
                "GitHub": {"status": "FOUND", "url": "https://github.com/alice", "display_name": "Alice Old", "avatar_hash": "old-hash"},
                "SoundCloud": {"status": "FOUND", "url": "https://soundcloud.com/alice", "display_name": "Alice Old", "avatar_hash": "old-hash"},
            },
        },
        {
            "timestamp": "2026-07-11T10:00:00+00:00",
            "results": {
                "GitHub": {"status": "FOUND", "url": "https://github.com/alice", "display_name": "Alice New", "avatar_hash": "new-hash"},
                "SoundCloud": {"status": "FOUND", "url": "https://soundcloud.com/alice", "display_name": "Alice New", "avatar_hash": "new-hash"},
            },
        },
    ]
    monkeypatch.setattr("argis.entrypoint.load_history", lambda username: history)
    result = runner.invoke(app, ["echo", "alice"])
    assert result.exit_code == 0
    assert "ARGIS ECHO" in result.stdout
    assert "identity rebrand" in result.stdout


def test_echo_can_write_json(monkeypatch, tmp_path):
    history = [
        {"timestamp": "2026-07-10T10:00:00Z", "results": {}},
        {"timestamp": "2026-07-11T10:00:00Z", "results": {}},
    ]
    monkeypatch.setattr("argis.entrypoint.load_history", lambda username: history)
    output = tmp_path / "echo-report"
    result = runner.invoke(app, ["echo", "alice", "-o", str(output)])
    assert result.exit_code == 0
    report = json.loads((tmp_path / "echo-report.json").read_text("utf-8"))
    assert report["username"] == "alice"
    assert report["snapshots_analyzed"] == 2
