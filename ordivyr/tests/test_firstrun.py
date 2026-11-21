"""First-run experience: init, config defaults, memory CLI, history, diagnose/repair. Real CLI subprocesses, no network."""
import json, os, sqlite3, stat, subprocess, sys, time
from pathlib import Path
import pytest
from ordivyr import firstrun as FR, durable as D

ROOT = Path(__file__).resolve().parents[2]


def cli(*args, home=None, input=None):
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT), "HOME": str(home or "/nonexistent"), "ORDIVYR_HOME": str(home or "")}
    p = subprocess.run([sys.executable, "-m", "ordivyr", *args], capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=120, input=input)
    return p.returncode, p.stdout, p.stderr


def test_init_creates_private_config_and_working_nova_memory(tmp_path):
    h = tmp_path / "home"
    rc, out, err = cli("init", "--home", str(h)); assert rc == 0, err
    cfg = json.loads((h / "config.json").read_text()); assert cfg["memory"]["backend"] == "nova" and cfg["provider"]["kind"] == "none"
    assert stat.S_IMODE(os.stat(h / "config.json").st_mode) == 0o600 and stat.S_IMODE(os.stat(h).st_mode) == 0o700
    rc, out, err = cli("init", "--home", str(h)); assert rc == 2 and "exists" in err                       # never silently overwrites
    assert cli("memory", "--home", str(h), "add", "deploys use the blue green script", "--kind", "procedural", "--ns", "shared")[0] == 0
    rc, out, _ = cli("memory", "--home", str(h), "search", "deploying"); assert rc == 0 and "blue green" in out
    assert cli("memory", "--home", str(h), "stats", "--ns", "shared")[0] == 0


def test_no_account_no_cloud_needed_run_uses_config_defaults(tmp_path):
    h = tmp_path / "home"; assert cli("init", "--home", str(h))[0] == 0
    from ordivyr import core
    b = core.new_board("t"); b["agents"].append(core.new_agent(0, 0, "Solo", id="solo")); (tmp_path / "b.json").write_text(json.dumps(b))          # free deterministic model: no endpoint, no account
    rc, out, err = cli("run", str(tmp_path / "b.json"), "--mission", "say hello", "--home", str(h), "--json"); assert rc == 0, err
    hist = json.loads(cli("history", "--home", str(h))[1]); assert hist["tasks"] and all(t["state"] == "completed" for t in hist["tasks"])     # durable store came from the config


def test_init_requires_url_for_provider_and_probe_reports_unreachable(tmp_path):
    rc, out, err = cli("init", "--home", str(tmp_path / "a"), "--provider", "openai"); assert rc == 2 and "--url" in err
    rc, out, err = cli("init", "--home", str(tmp_path / "b"), "--provider", "openai", "--url", "http://127.0.0.1:9/v1", "--check")
    assert rc == 0 and json.loads(out)["endpoint"]["ok"] is False                                          # config still written; problem reported, not hidden
    r = json.loads(cli("diagnose", "--home", str(tmp_path / "b"))[1]); bad = [c for c in r["checks"] if not c["ok"]]
    assert bad and bad[0]["check"] == "model endpoint" and "repair" in bad[0]


def test_diagnose_detects_and_fixes_dead_worker_and_loose_permissions(tmp_path):
    h = tmp_path / "home"; cli("init", "--home", str(h)); cfg = json.loads((h / "config.json").read_text())
    st = D.Store(cfg["durable_db"], clock=time.time); tid = st.submit("x", {}); t = st.claim("dead-worker", "main", 0.05); st.begin(tid, t["fence"]); time.sleep(0.15)       # worker "crashes"
    os.chmod(cfg["memory"]["db"], 0o644)
    rc, out, _ = cli("diagnose", "--home", str(h)); r = json.loads(out); assert rc == 1
    names = {c["check"] for c in r["checks"] if not c["ok"]}; assert "expired leases" in names and "private file nova.db" in names
    rc, out, _ = cli("diagnose", "--home", str(h), "--fix"); assert rc == 0, out
    assert D.Store(cfg["durable_db"]).claim("w2") is not None                                               # task is claimable again after the repair


def test_tampered_memory_surfaces_in_diagnose(tmp_path):
    h = tmp_path / "home"; cli("init", "--home", str(h)); cfg = json.loads((h / "config.json").read_text())
    rc, out, _ = cli("memory", "--home", str(h), "add", "fact to forge", "--ns", "shared"); mid = json.loads(out)["id"]
    c = sqlite3.connect(cfg["memory"]["db"]); c.execute("UPDATE mem SET trust='verified' WHERE id=?", (mid,)); c.commit(); c.close()
    r = json.loads(cli("diagnose", "--home", str(h))[1]); assert any(c["check"] == "memory integrity" and not c["ok"] for c in r["checks"])
