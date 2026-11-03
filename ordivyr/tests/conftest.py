import os, re, sys, pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """No test may read the real home: no ~/.config keys, no ~/.hermes, no ~/.jev-fleet."""
    h = tmp_path / "home"; h.mkdir(); monkeypatch.setenv("HOME", str(h))
    for k in list(os.environ):                      # nothing configured on the developer's machine may influence a test
        if k.startswith("ORDIVYR_") or re.search(r"KEY|TOKEN|SECRET|PASSWORD|URL", k): monkeypatch.delenv(k, raising=False)
    return h
