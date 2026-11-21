"""CLI-level acceptance: run transcripts must persist to disk."""
import json
from pathlib import Path

import pytest

from ordivyr import cli


@pytest.fixture
def board(tmp_path):
    b = {
        "schema": 1,
        "name": "Transcript Test",
        "version": 1,
        "agents": [
            {"id": "a1", "name": "Planner", "model": "det.01", "instructions": "plan",
             "tools": [], "permissions": "read-only", "subagents": {"enabled": False},
             "limits": {"token_budget": 60000, "spend_cap_usd": 0.0, "max_seconds": 600, "concurrency": 1},
             "memory": {"private": True, "shared": [], "mode": "read"}},
            {"id": "a2", "name": "Worker", "model": "det.01", "instructions": "do",
             "tools": [], "permissions": "read-only", "subagents": {"enabled": False},
             "limits": {"token_budget": 60000, "spend_cap_usd": 0.0, "max_seconds": 600, "concurrency": 1},
             "memory": {"private": True, "shared": [], "mode": "read"}, "depends_on": ["a1"]},
        ],
        "edges": [{"id": "e1", "from": "a1", "to": "a2"}],
    }
    p = tmp_path / "board.json"
    p.write_text(json.dumps(b))
    return p


def test_run_transcript_persisted_by_default(tmp_path, board, capsys):
    home = tmp_path / "state"
    rc = cli.main(["run", str(board), "--mission", "test mission", "--home", str(home)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "transcript:" in out
    runs_dir = home / "runs"
    files = list(runs_dir.glob("run-*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text())
    assert data["status"] == "done"
    assert "log_path" not in data  # transcript payload is the raw run result
    assert data["agents"]["a2"]["status"] == "done"


def test_run_transcript_custom_log_and_disable(tmp_path, board, capsys):
    custom = tmp_path / "x" / "custom.json"
    home = tmp_path / "state2"
    rc = cli.main(["run", str(board), "--mission", "m", "--home", str(home), "--log", str(custom)])
    assert rc == 0 and custom.exists()
    capsys.readouterr()
    assert json.loads(custom.read_text())["status"] == "done"
    assert not (home / "runs").exists()
    home3 = tmp_path / "state3"
    rc = cli.main(["run", str(board), "--mission", "m", "--home", str(home3), "--log", "none"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "transcript:" not in out and not (home3 / "runs").exists()


def test_transcript_file_is_owner_only(tmp_path, board):
    import stat
    home = tmp_path / "state"
    assert cli.main(["run", str(board), "--mission", "m", "--home", str(home)]) == 0
    (f,) = (home / "runs").glob("run-*.json")
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
